package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rs/cors"
	"gopkg.in/yaml.v3"
)

// Config describes runtime settings. Most values can be overridden by env.
type Config struct {
	GANCmdHome           string
	GANLogHome           string
	GANRunEnv            string
	UserDBFile           string
	UserTokenFile        string
	GitlabSecretToken    string
	GitlabCommitEnvCheck bool
	GitlabHookSendEmail  bool
	HandHookSendEmail    bool
	XZZXiaSignCheck      bool
	XZZXiaSignSecret     string
	ListenAddr           string
}

// loadYAMLConfig reads a YAML file into a string map (all values treated as string).
func loadYAMLConfig(path string) (map[string]string, error) {
	raw := make(map[string]string)
	data, err := os.ReadFile(path)
	if err != nil {
		return raw, err
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return raw, err
	}
	return raw, nil
}

func loadConfig() Config {
	// Defaults mirror python版 gan_api_var.py
	defaults := map[string]string{
		"GAN_CMD_HOME":                "../zzxia-op-super-invincible-lollipop",
		"GAN_LOG_HOME":                "../log",
		"GAN_RUN_ENV":                 "dev",
		"USER_DB_FILE":                "../my_sec/user.db",
		"USER_TOKEN_FILE":             "../my_sec/user.db.token",
		"GITLAB_SECRET_TOKEN":         "1234567890zxc",
		"GITLAB_GIT_COMMIT_ENV_CHECK": "YES",
		"GITLAB_HOOK_SEND_EMAIL":      "YES",
		"HAND_HOOK_SEND_EMAIL":        "NO",
		"X_ZZXIA_SIGN_CHECK":          "NO",
		"X_ZZXIA_SIGN_SECRET":         "setYourselfSigncharStringHere",
		"LISTEN_ADDR":                 ":9527",
	}

	// Load YAML (optional). Default path: ../config.yaml relative to go dir; override by CONFIG_FILE env.
	configFile := os.Getenv("CONFIG_FILE")
	if configFile == "" {
		configFile = "../config.yaml"
	}
	if yamlMap, err := loadYAMLConfig(configFile); err == nil {
		for k, v := range yamlMap {
			if strings.TrimSpace(v) != "" {
				defaults[k] = v
			}
		}
	}

	envOrValue := func(key string) string {
		if v := os.Getenv(key); v != "" {
			return v
		}
		return defaults[key]
	}

	toBool := func(v string) bool {
		v = strings.ToUpper(strings.TrimSpace(v))
		return v == "YES" || v == "TRUE" || v == "1"
	}

	return Config{
		GANCmdHome:           envOrValue("GAN_CMD_HOME"),
		GANLogHome:           envOrValue("GAN_LOG_HOME"),
		GANRunEnv:            envOrValue("GAN_RUN_ENV"),
		UserDBFile:           envOrValue("USER_DB_FILE"),
		UserTokenFile:        envOrValue("USER_TOKEN_FILE"),
		GitlabSecretToken:    envOrValue("GITLAB_SECRET_TOKEN"),
		GitlabCommitEnvCheck: toBool(envOrValue("GITLAB_GIT_COMMIT_ENV_CHECK")),
		GitlabHookSendEmail:  toBool(envOrValue("GITLAB_HOOK_SEND_EMAIL")),
		HandHookSendEmail:    toBool(envOrValue("HAND_HOOK_SEND_EMAIL")),
		XZZXiaSignCheck:      toBool(envOrValue("X_ZZXIA_SIGN_CHECK")),
		XZZXiaSignSecret:     envOrValue("X_ZZXIA_SIGN_SECRET"),
		ListenAddr:           envOrValue("LISTEN_ADDR"),
	}
}

type server struct {
	cfg Config
}

func main() {
	cfg := loadConfig()
	if err := os.MkdirAll(cfg.GANLogHome, 0o755); err != nil {
		log.Fatalf("创建日志目录失败: %v", err)
	}

	s := &server{cfg: cfg}

	mux := http.NewServeMux()
	mux.HandleFunc("/get/token", s.handleGetToken)
	mux.HandleFunc("/hook/gitlab", s.handleHookGitlab)
	mux.HandleFunc("/hook/hand", s.handleHookHand)

	handler := cors.AllowAll().Handler(loggingMiddleware(mux))
	log.Printf("Go 版 gan-api-server 启动，监听 %s", cfg.ListenAddr)
	if err := http.ListenAndServe(cfg.ListenAddr, handler); err != nil {
		log.Fatalf("服务启动失败: %v", err)
	}
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

// ---- 通用工具 ----

func digestSHA256(msg string) string {
	sum := sha256.Sum256([]byte(msg))
	return hex.EncodeToString(sum[:])
}

func digestSHA256Salt(salt, msg string) string {
	return digestSHA256(salt + msg)
}

func digestHMACSHA1(key string, body []byte) string {
	h := hmac.New(sha1.New, []byte(key))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, sc.Err()
}

func isCommentOrEmpty(line string) bool {
	trim := strings.TrimSpace(line)
	return trim == "" || strings.HasPrefix(trim, "#")
}

// 去除 ANSI 控制字符，便于生成 .txt 日志
func stripControlCodes(b []byte) []byte {
	reAnsi := regexp.MustCompile(`\x1B\[[0-9;]*[A-Za-z]`)
	b = reAnsi.ReplaceAll(b, nil)
	b = bytes.ReplaceAll(b, []byte{'\r'}, nil)
	return b
}

func writeCleanLog(src, dest string) error {
	raw, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	clean := stripControlCodes(raw)
	return os.WriteFile(dest, clean, 0o644)
}

func runShell(cmd string, env []string) error {
	c := exec.Command("bash", "-c", cmd)
	if len(env) > 0 {
		c.Env = append(os.Environ(), env...)
	}
	return c.Run()
}

func runShellStream(cmd string, env []string, stdout io.Writer) error {
	c := exec.Command("bash", "-c", cmd)
	if len(env) > 0 {
		c.Env = append(os.Environ(), env...)
	}

	// Combine stdout and stderr
	c.Stdout = stdout
	c.Stderr = stdout

	return c.Run()
}

func jsonResponse(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// ---- 认证 ----

func (s *server) authUserPW(user, sec string) (map[string]string, error) {
	lines, err := readLines(s.cfg.UserDBFile)
	if err != nil {
		return nil, fmt.Errorf("读取用户库失败: %w", err)
	}
	for _, line := range lines {
		if isCommentOrEmpty(line) {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 7 {
			return nil, errors.New("服务器用户信息异常")
		}
		lineUser := strings.TrimSpace(parts[2])
		lineSalt := strings.TrimSpace(parts[5])
		lineSecret := strings.TrimSpace(parts[6])
		if lineUser != user {
			continue
		}
		if len(sec) < 32 {
			return nil, errors.New("用户名密码错")
		}
		newSec := sec[2:32]
		secret := digestSHA256Salt(lineSalt, newSec)
		if len(secret) < 53 {
			return nil, errors.New("服务器用户信息异常")
		}
		newSecret := secret[3:53]
		if newSecret == lineSecret {
			return map[string]string{"Status": "Success", "Message": "验证成功"}, nil
		}
		return nil, errors.New("用户名密码错")
	}
	return nil, errors.New("用户名不存在")
}

func (s *server) authUserToken(token string) (string, error) {
	lines, err := readLines(s.cfg.UserTokenFile)
	if err != nil {
		return "", fmt.Errorf("读取 Token 库失败: %w", err)
	}
	for _, line := range lines {
		if isCommentOrEmpty(line) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return "", errors.New("Token 库信息异常")
		}
		if fields[1] == token {
			return fields[0], nil
		}
	}
	return "", errors.New("Token 库中未找到")
}

func (s *server) getUserToken(user string) (string, error) {
	lines, err := readLines(s.cfg.UserTokenFile)
	if err != nil {
		return "", fmt.Errorf("读取 Token 库失败: %w", err)
	}
	for _, line := range lines {
		if isCommentOrEmpty(line) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return "", errors.New("Token 库信息异常")
		}
		if fields[0] == user {
			return fields[1], nil
		}
	}
	return "", errors.New("Token 库中未找到")
}

func (s *server) getUserInfo(user string) (string, string, error) {
	lines, err := readLines(s.cfg.UserDBFile)
	if err != nil {
		return "", "", fmt.Errorf("读取用户库失败: %w", err)
	}
	for _, line := range lines {
		if isCommentOrEmpty(line) {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 5 {
			return "", "", errors.New("服务器用户信息异常")
		}
		lineUser := strings.TrimSpace(parts[2])
		lineXingming := strings.TrimSpace(parts[3])
		lineEmail := strings.TrimSpace(parts[4])
		if lineUser == user {
			return lineXingming, lineEmail, nil
		}
	}
	return "", "", errors.New("用户信息不存在")
}

// ---- 处理器 ----

func (s *server) handleGetToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	user := r.Header.Get("user")
	sec := r.Header.Get("sec")
	if user == "" || sec == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"Status": "Error", "Message": "请提供登录信息"})
		return
	}
	if _, err := s.authUserPW(user, sec); err != nil {
		jsonResponse(w, http.StatusUnauthorized, map[string]string{"Status": "Error", "Message": err.Error()})
		return
	}
	token, err := s.getUserToken(user)
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"Status": "Error", "Message": err.Error()})
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"Status": "Success", "Token": token})
}

// Body helper
func decodeJSONBody(r *http.Request) (map[string]any, []byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, nil, err
	}
	defer r.Body.Close()
	var kv map[string]any
	if err := json.Unmarshal(body, &kv); err != nil {
		return nil, body, err
	}
	return kv, body, nil
}

func getStringAtPath(m map[string]any, path ...string) string {
	var cur any = m
	for _, p := range path {
		asMap, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur, ok = asMap[p]
		if !ok {
			return ""
		}
	}
	switch v := cur.(type) {
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	}
	return ""
}

func getInt(m map[string]any, key string) int {
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case string:
		i, _ := strconv.Atoi(t)
		return i
	}
	return 0
}

func parseCommitArgs(msg string) (ganEnv, ganDo, ganVersion, ganGray, ganSkiptest string) {
	start := strings.Index(msg, "{")
	end := strings.Index(msg, "}")
	if start == -1 || end == -1 || end <= start {
		return
	}
	seg := strings.ToLower(strings.ReplaceAll(msg[start+1:end], " ", ""))
	seg = strings.ReplaceAll(seg, `"`, "")
	seg = strings.ReplaceAll(seg, "'", "")
	for _, kv := range strings.Split(seg, ",") {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		k := parts[0]
		v := parts[1]
		switch k {
		case "env":
			ganEnv = v
		case "do":
			ganDo = v
		case "version":
			ganVersion = v
		case "gray":
			ganGray = v
		case "skiptest":
			ganSkiptest = v
		}
	}
	return
}

func (s *server) handleHookGitlab(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	hookTime := time.Now().Format("2006-01-02_T_150405")
	gitlabToken := r.Header.Get("X-Gitlab-Token")
	if gitlabToken != s.cfg.GitlabSecretToken {
		jsonResponse(w, http.StatusUnauthorized, map[string]string{"Status": "Error", "Message": "Token错误"})
		return
	}

	kv, _, err := decodeJSONBody(r)
	if err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"Status": "Error", "Message": "JSON解析失败"})
		return
	}

	project := getStringAtPath(kv, "repository", "name")
	ref := getStringAtPath(kv, "ref")
	refParts := strings.Split(ref, "/")
	branch := ""
	if len(refParts) >= 3 {
		branch = refParts[2]
	}
	userName := getStringAtPath(kv, "user_username")
	userXingming := getStringAtPath(kv, "user_name")
	commitsCount := getInt(kv, "total_commits_count")

	// commits 数组
	var commits []any
	if v, ok := kv["commits"]; ok {
		if arr, ok := v.([]any); ok {
			commits = arr
		}
	}
	getCommitField := func(idx int, field string) string {
		if idx < 0 || idx >= len(commits) {
			return ""
		}
		if m, ok := commits[idx].(map[string]any); ok {
			switch field {
			case "message":
				if v, ok := m["message"].(string); ok {
					return v
				}
			case "author.email":
				if a, ok := m["author"].(map[string]any); ok {
					if v, ok := a["email"].(string); ok {
						return v
					}
				}
			}
		}
		return ""
	}
	lastIdx := commitsCount - 1
	commitMsg := getCommitField(lastIdx, "message")
	commitEmail := getCommitField(lastIdx, "author.email")

	ganEnv, ganDo, ganVersion, ganGray, ganSkiptest := parseCommitArgs(commitMsg)

	if s.cfg.GitlabCommitEnvCheck {
		if ganEnv == "" {
			jsonResponse(w, http.StatusBadRequest, map[string]string{"Status": "Error", "Message": "Webhook信息之【env】不存在"})
			return
		}
		if ganEnv != s.cfg.GANRunEnv {
			jsonResponse(w, http.StatusOK, map[string]string{"Status": "Info", "Message": "Webhook信息之【env】与当前环境不匹配，跳过"})
			return
		}
	} else if ganEnv == "" {
		ganEnv = "NOT_CHECK"
	}

	// 构建命令
	baseEnv := []string{
		"HOOK_USER_INFO_FROM=hook_gitlab",
		"HOOK_GAN_ENV=" + ganEnv,
		"HOOK_USER_NAME=" + userName,
		"HOOK_USER_XINGMING=" + userXingming,
		"HOOK_USER_EMAIL=" + commitEmail,
	}

	var cmd string
	switch ganDo {
	case "":
		cmd = filepath.Join(s.cfg.GANCmdHome, "deploy/gogogo.sh")
	case "build":
		cmd = filepath.Join(s.cfg.GANCmdHome, "deploy/build.sh")
	case "gogogo":
		cmd = filepath.Join(s.cfg.GANCmdHome, "deploy/gogogo.sh")
	default:
		jsonResponse(w, http.StatusBadRequest, map[string]string{"Status": "Error", "Message": "Webhook信息之【do】不存在、错误或超出范围"})
		return
	}
	if ganDo == "gogogo" && ganVersion != "" {
		cmd += " --release-version " + ganVersion
	}
	if matched, _ := regexp.MatchString(`(?i)^yes|^y`, ganGray); matched {
		cmd += " --gray "
	}
	if matched, _ := regexp.MatchString(`(?i)^yes|^y`, ganSkiptest); matched {
		cmd += " --skiptest "
	}
	cmd += " --branch " + branch + " ^" + project + "$"

	logfile := filepath.Join(s.cfg.GANLogHome, fmt.Sprintf("webhook_gitlab--%s--%s.log", hookTime, project))
	fullCmd := strings.Join([]string{
		strings.Join(baseEnv, " "),
		cmd + " > " + logfile + " 2>&1",
	}, " ; ")

	if err := runShell(fullCmd, nil); err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"Status": "Error", "Message": err.Error()})
		return
	}

	logTxt := strings.TrimSuffix(logfile, ".log") + ".txt.log"
	if err := writeCleanLog(logfile, logTxt); err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"Status": "Error", "Message": "生成日志失败"})
		return
	}

	if s.cfg.GitlabHookSendEmail && commitEmail != "" {
		sendMail := fmt.Sprintf("%s/tools/send_mail.sh --subject \"webhook_gitlab日志\" --content \"$(cat %s)\" %s",
			s.cfg.GANCmdHome, logTxt, commitEmail)
		_ = runShell(sendMail, nil)
	}

	jsonResponse(w, http.StatusOK, map[string]string{"Status": "OK", "Logfile": logTxt})
}

type handBody struct {
	Do       string   `json:"do"`
	Lise     string   `json:"lise"`
	Number   string   `json:"number"`
	Category string   `json:"category"`
	Branch   string   `json:"branch"`
	ImgPre   string   `json:"image-pre-name"`
	Email    string   `json:"email"`
	SkipTest string   `json:"skiptest"`
	Force    string   `json:"force"`
	Verbose  string   `json:"verbose"`
	Gray     string   `json:"gray"`
	Version  string   `json:"version"`
	Extra    string   `json:"extra"`
	Projects []string `json:"projects"`
}

func (s *server) handleHookHand(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	hookTime := time.Now().Format("2006-01-02_T_150405")
	rawBody, err := io.ReadAll(r.Body)
	if err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"Status": "Error", "Message": "读取请求失败"})
		return
	}
	defer r.Body.Close()

	token := r.Header.Get("token")
	user := r.Header.Get("user")
	sec := r.Header.Get("sec")
	sign := r.Header.Get("X-ZZXia-Signature")

	if token == "" && (user == "" || sec == "") {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"Status": "Error", "Message": "请提供登录信息"})
		return
	}

	if token != "" {
		verifiedUser, err := s.authUserToken(token)
		if err != nil {
			jsonResponse(w, http.StatusUnauthorized, map[string]string{"Status": "Error", "Message": err.Error()})
			return
		}
		user = verifiedUser
	} else {
		if _, err := s.authUserPW(user, sec); err != nil {
			jsonResponse(w, http.StatusUnauthorized, map[string]string{"Status": "Error", "Message": err.Error()})
			return
		}
	}

	if s.cfg.XZZXiaSignCheck {
		serverSign := digestHMACSHA1(s.cfg.XZZXiaSignSecret, rawBody)
		if sign != serverSign {
			jsonResponse(w, http.StatusUnauthorized, map[string]string{"Status": "Error", "Message": "X-ZZXia-Signature 验证失败"})
			return
		}
	}

	var body handBody
	if err := json.Unmarshal(rawBody, &body); err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"Status": "Error", "Message": "JSON解析失败"})
		return
	}

	userXingming, userEmail, err := s.getUserInfo(user)
	if err != nil {
		jsonResponse(w, http.StatusUnauthorized, map[string]string{"Status": "Error", "Message": err.Error()})
		return
	}

	if body.Do == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"Status": "Error", "Message": "Webhook信息不存在或错误"})
		return
	}

	baseEnv := []string{
		"HOOK_USER_INFO_FROM=hook_hand",
		"HOOK_USER_NAME=" + user,
		"HOOK_USER_XINGMING=" + userXingming,
		"HOOK_USER_EMAIL=" + userEmail,
	}

	var cmd string
	switch body.Do {
	case "build":
		cmd = filepath.Join(s.cfg.GANCmdHome, "deploy/build.sh")
	case "build-parallel":
		cmd = filepath.Join(s.cfg.GANCmdHome, "deploy/build-parallel.sh")
	case "gogogo":
		cmd = filepath.Join(s.cfg.GANCmdHome, "deploy/gogogo.sh")
	case "docker-deploy", "docker-cluster-service-deploy":
		cmd = filepath.Join(s.cfg.GANCmdHome, "deploy/docker-cluster-service-deploy.sh")
	case "web-release":
		cmd = filepath.Join(s.cfg.GANCmdHome, "deploy/web-release.sh")
	case "deploy":
		cmd = filepath.Join(s.cfg.GANCmdHome, "deploy/deploy.sh")
	default:
		jsonResponse(w, http.StatusBadRequest, map[string]string{"Status": "Error", "Message": "Webhook信息之【do】不存在或错误"})
		return
	}

	if strings.Contains(body.Do, "deploy") {
		if len(body.Projects) > 0 {
			cmd += " " + strings.Join(body.Projects, " ")
		}
	} else {
		if body.Branch != "" {
			cmd += " --branch " + body.Branch
		}
		if matched, _ := regexp.MatchString(`(?i)^yes|^y`, body.SkipTest); matched {
			cmd += " --skiptest "
		}
		if matched, _ := regexp.MatchString(`(?i)^yes|^y`, body.Force); matched {
			cmd += " --force "
		}
		if body.Category != "" {
			cmd += " --category " + body.Category
		}
		if body.Extra != "" {
			cmd += " " + body.Extra
		}
		if len(body.Projects) > 0 {
			cmd += " " + strings.Join(body.Projects, " ")
		}
		if body.Do == "gogogo" {
			if body.Version != "" {
				cmd += " --release-version " + body.Version
			}
			if matched, _ := regexp.MatchString(`(?i)^yes|^y`, body.Gray); matched {
				cmd += " --gray "
			}
		}
	}

	logfile := filepath.Join(s.cfg.GANLogHome, fmt.Sprintf("webhook_hand--%s.log", hookTime))

	// Create log file
	f, err := os.Create(logfile)
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"Status": "Error", "Message": "创建日志文件失败: " + err.Error()})
		return
	}
	defer f.Close()

	// Prepare streaming response
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// Flush immediately to send headers
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
		// Wrap w with a flushing writer
		w = &flushWriter{ResponseWriter: w}
	}

	// MultiWriter to write to both file and response
	mw := io.MultiWriter(f, w)

	// Construct command string for display/logging (without redirection)
	fullCmd := strings.Join([]string{
		strings.Join(baseEnv, " "),
		cmd,
	}, " ; ")

	// Execute synchronously with streaming
	// Note: runShellStream takes the *full command line* if passed to bash -c,
	// but here we are constructing it. Ideally we pass the full string to bash -c.
	// The original code successfully ran `fullCmd` which included redirection.
	// Here `fullCmd` is just the env vars + script path + args.
	if err := runShellStream(fullCmd, nil, mw); err != nil {
		// Log error to stream too
		fmt.Fprintf(mw, "\nExecution failed: %v\n", err)
	}

	logTxt := strings.TrimSuffix(logfile, ".log") + ".txt.log"
	// We need to close 'f' or ensure content is flushed before reading it for cleanLog
	f.Sync()
	// Re-open for cleaning (or just rely on what was written)
	// Note: writeCleanLog reads from src (logfile). Since f is deferred close, we might need to close it explicitly if we want to read it immediately?
	// Actually, defer f.Close() happens after this function returns.
	// But writeCleanLog opens the file itself.
	// To be safe, we should probably close f before calling writeCleanLog, or assume os.ReadFile works on open files (linux usually fine).
	// Better: close it now.
	f.Close()

	if err := writeCleanLog(logfile, logTxt); err != nil {
		// Cannot send JSON response as we already sent text stream.
		// Just log to console
		log.Printf("生成日志失败: %v", err)
	} else {
		if s.cfg.HandHookSendEmail && userEmail != "" {
			sendMail := fmt.Sprintf("%s/tools/send_mail.sh --subject \"webhook_hand日志\" --content \"$(cat %s)\" %s",
				s.cfg.GANCmdHome, logTxt, userEmail)
			_ = runShell(sendMail, nil)
		}
	}

	// Response is already sent via stream.
}

type flushWriter struct {
	http.ResponseWriter
}

func (fw *flushWriter) Write(p []byte) (int, error) {
	n, err := fw.ResponseWriter.Write(p)
	if f, ok := fw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
	return n, err
}
