package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/cors"
	"gopkg.in/yaml.v3"
)

// Config describes runtime settings. Most values can be overridden by env.
type Config struct {
	GANCmdHome           string
	GANLogHome           string
	GANRunEnv            string
	UserDBFile           string
	GitlabSecretToken    string
	GitlabCommitEnvCheck bool
	GitlabHookSendEmail  bool
	HandHookSendEmail    bool
	ListenAddr           string
	// JWT 配置
	JWTSecret          string
	JWTExpirationHours int
	// HTTPS 配置
	EnableHTTPS bool
	TLSCertFile string
	TLSKeyFile  string
	// CORS 配置
	EnableStrictCORS   bool
	CORSAllowedOrigins []string
	// Cookie 配置
	UseCookieAuth bool
	// 调试模式
	DebugMode bool
}

// 全局调试标志
var debugMode bool

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
		"GITLAB_SECRET_TOKEN":         "1234567890zxc",
		"GITLAB_GIT_COMMIT_ENV_CHECK": "YES",
		"GITLAB_HOOK_SEND_EMAIL":      "YES",
		"HAND_HOOK_SEND_EMAIL":        "NO",
		"LISTEN_ADDR":                 ":9527",
		// JWT 配置
		"JWT_SECRET":           "your-very-secure-random-secret-key-change-me-please",
		"JWT_EXPIRATION_HOURS": "8",
		// HTTPS 配置
		"ENABLE_HTTPS":  "NO",
		"TLS_CERT_FILE": "",
		"TLS_KEY_FILE":  "",
		// CORS 配置
		"ENABLE_STRICT_CORS":   "NO",
		"CORS_ALLOWED_ORIGINS": "https://yourdomain.com,http://localhost:3000",
		// Cookie 配置
		"USE_COOKIE_AUTH": "YES",
		// 调试模式
		"DEBUG_MODE": "NO",
	}

	// Load YAML (optional). Default path: ../config.yaml relative to go dir; override by CONFIG_FILE env.
	yamlConfig := map[string]string{}
	configFile := os.Getenv("CONFIG_FILE")
	if configFile == "" {
		configFile = "../config.yaml"
	}
	if yamlMap, err := loadYAMLConfig(configFile); err == nil {
		for k, v := range yamlMap {
			if strings.TrimSpace(v) != "" {
				yamlConfig[k] = v
			}
		}
	}

	// 配置优先级: YAML 配置 > 环境变量 > 默认值
	getValue := func(key string) string {
		// 1. 优先使用 YAML 配置
		if v, ok := yamlConfig[key]; ok && v != "" {
			return v
		}
		// 2. 其次使用环境变量
		if v := os.Getenv(key); v != "" {
			return v
		}
		// 3. 最后使用默认值
		return defaults[key]
	}

	toBool := func(v string) bool {
		v = strings.ToUpper(strings.TrimSpace(v))
		return v == "YES" || v == "TRUE" || v == "1"
	}

	toInt := func(v string, defaultVal int) int {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
		return defaultVal
	}

	// Parse CORS allowed origins
	corsOrigins := []string{}
	originsStr := getValue("CORS_ALLOWED_ORIGINS")
	if originsStr != "" {
		for _, origin := range strings.Split(originsStr, ",") {
			if trimmed := strings.TrimSpace(origin); trimmed != "" {
				corsOrigins = append(corsOrigins, trimmed)
			}
		}
	}

	return Config{
		GANCmdHome:           getValue("GAN_CMD_HOME"),
		GANLogHome:           getValue("GAN_LOG_HOME"),
		GANRunEnv:            getValue("GAN_RUN_ENV"),
		UserDBFile:           getValue("USER_DB_FILE"),
		GitlabSecretToken:    getValue("GITLAB_SECRET_TOKEN"),
		GitlabCommitEnvCheck: toBool(getValue("GITLAB_GIT_COMMIT_ENV_CHECK")),
		GitlabHookSendEmail:  toBool(getValue("GITLAB_HOOK_SEND_EMAIL")),
		HandHookSendEmail:    toBool(getValue("HAND_HOOK_SEND_EMAIL")),
		ListenAddr:           getValue("LISTEN_ADDR"),
		// JWT 配置
		JWTSecret:          getValue("JWT_SECRET"),
		JWTExpirationHours: toInt(getValue("JWT_EXPIRATION_HOURS"), 8),
		// HTTPS 配置
		EnableHTTPS: toBool(getValue("ENABLE_HTTPS")),
		TLSCertFile: getValue("TLS_CERT_FILE"),
		TLSKeyFile:  getValue("TLS_KEY_FILE"),
		// CORS 配置
		EnableStrictCORS:   toBool(getValue("ENABLE_STRICT_CORS")),
		CORSAllowedOrigins: corsOrigins,
		// Cookie 配置
		UseCookieAuth: toBool(getValue("USE_COOKIE_AUTH")),
		// 调试模式
		DebugMode: toBool(getValue("DEBUG_MODE")),
	}
}

type server struct {
	cfg Config
}

func getClientIP(r *http.Request) string {
	// 1. 尝试 X-Forwarded-For (格式: client, proxy1, proxy2)
	val := r.Header.Get("X-Forwarded-For")
	if val != "" {
		parts := strings.Split(val, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	// 2. 尝试 X-Real-IP
	val = r.Header.Get("X-Real-IP")
	if val != "" {
		return strings.TrimSpace(val)
	}
	// 3. 回退到 RemoteAddr (去除端口)
	addr := r.RemoteAddr
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

func main() {
	cfg := loadConfig()
	if err := os.MkdirAll(cfg.GANLogHome, 0o755); err != nil {
		log.Fatalf("创建日志目录失败: %v", err)
	}

	// 验证 JWT Secret
	if cfg.JWTSecret == "your-very-secure-random-secret-key-change-me-please" {
		log.Println("⚠️  警告: 请修改 JWT_SECRET 配置为随机字符串！")
	}

	s := &server{cfg: cfg}

	mux := http.NewServeMux()
	mux.HandleFunc("/get/token", s.handleGetToken)
	mux.HandleFunc("/hook/gitlab", s.handleHookGitlab)
	mux.HandleFunc("/hook/hand", s.handleHookHand)

	// 列表 API (需要认证)
	mux.HandleFunc("/get/list/project", s.authMiddleware(s.handleGetListProject))
	mux.HandleFunc("/get/list/docker-cluster-service", s.authMiddleware(s.handleGetListDockerClusterService))
	mux.HandleFunc("/get/list/nginx", s.authMiddleware(s.handleGetListNginx))

	// 配置 CORS
	var corsHandler *cors.Cors
	if cfg.EnableStrictCORS && len(cfg.CORSAllowedOrigins) > 0 {
		log.Printf("启用严格 CORS 限制，允许来源: %v", cfg.CORSAllowedOrigins)
		corsHandler = cors.New(cors.Options{
			AllowedOrigins:   cfg.CORSAllowedOrigins,
			AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
			AllowedHeaders:   []string{"Content-Type", "token", "user", "sec", "X-Gitlab-Token"},
			AllowCredentials: true,
			MaxAge:           300,
		})
	} else {
		log.Println("⚠️  CORS 允许所有来源（开发/测试模式）")
		// 使用 AllowOriginFunc 来动态返回请求的 Origin，支持 credentials
		corsHandler = cors.New(cors.Options{
			AllowOriginFunc: func(origin string) bool {
				// 开发模式允许所有来源
				return true
			},
			AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
			AllowedHeaders:   []string{"Content-Type", "token", "user", "sec", "X-Gitlab-Token"},
			AllowCredentials: true,
			MaxAge:           300,
		})
	}

	// 设置全局调试模式
	debugMode = cfg.DebugMode
	if debugMode {
		log.Println("🐛 调试模式已启用")
	}

	handler := corsHandler.Handler(securityHeadersMiddleware(loggingMiddleware(mux)))

	// 启动服务器
	if cfg.EnableHTTPS {
		if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
			log.Fatalf("启用 HTTPS 需要配置 TLS_CERT_FILE 和 TLS_KEY_FILE")
		}
		log.Printf("🔒 启动 HTTPS 服务器: %s", cfg.ListenAddr)
		log.Printf("   证书: %s", cfg.TLSCertFile)
		if err := http.ListenAndServeTLS(cfg.ListenAddr, cfg.TLSCertFile, cfg.TLSKeyFile, handler); err != nil {
			log.Fatalf("HTTPS 服务启动失败: %v", err)
		}
	} else {
		log.Printf("⚠️  启动 HTTP 服务器（不安全）: %s", cfg.ListenAddr)
		log.Println("   建议生产环境启用 HTTPS (ENABLE_HTTPS=YES)")
		if err := http.ListenAndServe(cfg.ListenAddr, handler); err != nil {
			log.Fatalf("HTTP 服务启动失败: %v", err)
		}
	}
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", getClientIP(r), r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		// 如果是 HTTPS，添加 HSTS
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
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
	if debugMode {
		log.Printf("[DEBUG] authUserPW: user=%s, sec=%s, sec_len=%d", user, sec, len(sec))
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
		if debugMode {
			log.Printf("[DEBUG] 找到用户: lineUser=%s, lineSalt=%s, lineSecret=%s", lineUser, lineSalt, lineSecret)
		}
		if len(sec) < 32 {
			if debugMode {
				log.Printf("[DEBUG] sec 长度不足: %d < 32", len(sec))
			}
			return nil, errors.New("用户名密码错")
		}
		newSec := sec[2:32]
		if debugMode {
			log.Printf("[DEBUG] newSec (sec[2:32]): %s", newSec)
		}
		secret := digestSHA256Salt(lineSalt, newSec)
		if debugMode {
			log.Printf("[DEBUG] digestSHA256Salt 结果: %s, len=%d", secret, len(secret))
		}
		if len(secret) < 53 {
			return nil, errors.New("服务器用户信息异常")
		}
		newSecret := secret[3:53]
		if debugMode {
			log.Printf("[DEBUG] newSecret (secret[3:53]): %s", newSecret)
			log.Printf("[DEBUG] 比对: newSecret=%s, lineSecret=%s, 相等=%v", newSecret, lineSecret, newSecret == lineSecret)
		}
		if newSecret == lineSecret {
			return map[string]string{"Status": "Success", "Message": "验证成功"}, nil
		}
		return nil, errors.New("用户名密码错")
	}
	return nil, errors.New("用户名不存在")
}

// authUserToken 验证 JWT Token
func (s *server) authUserToken(tokenString string) (string, error) {
	// 解析 JWT
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// 验证签名方法
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("意外的签名方法: %v", token.Header["alg"])
		}
		return []byte(s.cfg.JWTSecret), nil
	})

	if err != nil {
		return "", fmt.Errorf("token 解析失败: %w", err)
	}

	if !token.Valid {
		return "", errors.New("token 无效")
	}

	// 提取用户名
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("token Claims 格式错误")
	}

	username, ok := claims["username"].(string)
	if !ok {
		return "", errors.New("token 中缺少用户名")
	}

	return username, nil
}

// generateJWT 生成 JWT Token
func (s *server) generateJWT(username string) (string, error) {
	now := time.Now()
	expirationTime := now.Add(time.Duration(s.cfg.JWTExpirationHours) * time.Hour)

	claims := jwt.MapClaims{
		"username": username,
		"iat":      now.Unix(),
		"exp":      expirationTime.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(s.cfg.JWTSecret))
	if err != nil {
		return "", fmt.Errorf("token 生成失败: %w", err)
	}

	return tokenString, nil
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
	clientIP := getClientIP(r)
	user := r.Header.Get("user")
	sec := r.Header.Get("sec")
	if user == "" || sec == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"Status": "Error", "Message": "请提供登录信息"})
		return
	}

	// 验证用户名密码
	if _, err := s.authUserPW(user, sec); err != nil {
		log.Printf("[AUTH] 登录失败: user=%s ip=%s error=%v", user, clientIP, err)
		jsonResponse(w, http.StatusUnauthorized, map[string]string{"Status": "Error", "Message": "用户名或密码错误"})
		return
	}

	// 生成 JWT Token
	token, err := s.generateJWT(user)
	if err != nil {
		log.Printf("[AUTH] Token 生成失败: user=%s error=%v", user, err)
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"Status": "Error", "Message": "Token 生成失败"})
		return
	}

	log.Printf("[AUTH] 登录成功: user=%s ip=%s", user, clientIP)

	// 如果启用 Cookie 认证，设置 HttpOnly Cookie
	if s.cfg.UseCookieAuth {
		http.SetCookie(w, &http.Cookie{
			Name:     "auth_token",
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			Secure:   s.cfg.EnableHTTPS, // 仅在 HTTPS 时启用 Secure
			SameSite: http.SameSiteStrictMode,
			MaxAge:   s.cfg.JWTExpirationHours * 3600,
		})
	}

	// 返回 JSON (兼容旧版前端或不使用 Cookie 的情况)
	jsonResponse(w, http.StatusOK, map[string]string{
		"Status":  "Success",
		"Token":   token,
		"Message": "登录成功",
	})
}

// authMiddleware 认证中间件
func (s *server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)

		// 优先从 Cookie 读取 Token
		var token string
		cookie, err := r.Cookie("auth_token")
		if err == nil && cookie.Value != "" {
			token = cookie.Value
		} else {
			// 兼容旧方式: 从 Header 读取
			token = r.Header.Get("token")
		}

		if token == "" {
			jsonResponse(w, http.StatusUnauthorized, map[string]string{"Status": "Error", "Message": "未登录，请先登录"})
			return
		}

		// 验证 Token
		_, err = s.authUserToken(token)
		if err != nil {
			log.Printf("[AUTH] Token 验证失败: ip=%s error=%v", clientIP, err)
			jsonResponse(w, http.StatusUnauthorized, map[string]string{"Status": "Error", "Message": "Token 无效或已过期，请重新登录"})
			return
		}

		// 验证通过，继续处理
		next(w, r)
	}
}

// handleGetListProject 获取项目列表
func (s *server) handleGetListProject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	filePath := filepath.Join(s.cfg.GANCmdHome, "deploy/project.list")
	// project.list: 第0个字段是类别，第1个字段是项目名
	items, err := parseListFile(filePath, 0, 1)
	if err != nil {
		log.Printf("[LIST] 读取项目列表失败: %v", err)
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"Status": "Error", "Message": "读取项目列表失败"})
		return
	}

	jsonResponse(w, http.StatusOK, map[string]any{
		"Status": "Success",
		"Data":   items,
	})
}

// handleGetListDockerClusterService 获取微服务列表
func (s *server) handleGetListDockerClusterService(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	filePath := filepath.Join(s.cfg.GANCmdHome, "deploy/docker-cluster-service.list")
	// docker-cluster-service.list: 第0个字段是服务名，不需要类别
	items, err := parseListFile(filePath, -1, 0)
	if err != nil {
		log.Printf("[LIST] 读取微服务列表失败: %v", err)
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"Status": "Error", "Message": "读取微服务列表失败"})
		return
	}

	jsonResponse(w, http.StatusOK, map[string]any{
		"Status": "Success",
		"Data":   items,
	})
}

// handleGetListNginx 获取网站项目列表
func (s *server) handleGetListNginx(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	filePath := filepath.Join(s.cfg.GANCmdHome, "deploy/nginx.list")
	// nginx.list: 第0个字段是项目名，不需要类别
	items, err := parseListFile(filePath, -1, 0)
	if err != nil {
		log.Printf("[LIST] 读取网站项目列表失败: %v", err)
		jsonResponse(w, http.StatusInternalServerError, map[string]string{"Status": "Error", "Message": "读取网站项目列表失败"})
		return
	}

	jsonResponse(w, http.StatusOK, map[string]any{
		"Status": "Success",
		"Data":   items,
	})
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

type RunReq struct {
	Do             string   `json:"do"`
	Action         string   `json:"action"`
	Category       string   `json:"category"`
	Branch         string   `json:"branch"`
	SkipTest       string   `json:"skiptest"`
	Force          string   `json:"force"`
	Gray           string   `json:"gray"`
	ReleaseVersion string   `json:"release-version"`
	Extra          string   `json:"extra"`
	Projects       []string `json:"projects"`
}

// ListItem 表示列表项
type ListItem struct {
	Category string `json:"category"`
	Name     string `json:"name"`
}

// parseListFile 解析 .list 文件，返回列表项
// categoryIndex: 类别字段索引（-1 表示不提取类别）
// nameIndex: 名称字段索引
func parseListFile(filePath string, categoryIndex, nameIndex int) ([]ListItem, error) {
	lines, err := readLines(filePath)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败: %w", err)
	}

	var items []ListItem
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// 跳过注释和空行
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// 只处理以 | 开头的数据行
		if !strings.HasPrefix(trimmed, "|") {
			continue
		}

		// 分割字段
		parts := strings.Split(trimmed, "|")
		// 去除首尾空字段
		var fields []string
		for _, p := range parts {
			trimField := strings.TrimSpace(p)
			if trimField != "" {
				fields = append(fields, trimField)
			}
		}

		// 检查字段数量
		maxIndex := nameIndex
		if categoryIndex > maxIndex {
			maxIndex = categoryIndex
		}
		if len(fields) <= maxIndex {
			continue
		}

		item := ListItem{
			Name: fields[nameIndex],
		}
		if categoryIndex >= 0 && categoryIndex < len(fields) {
			item.Category = fields[categoryIndex]
		}
		items = append(items, item)
	}

	return items, nil
}

func buildShellCmd(req RunReq, cfg Config) (string, error) {
	var cmd string
	switch req.Do {
	case "build":
		cmd = filepath.Join(cfg.GANCmdHome, "deploy/build.sh")
	case "build-para", "build-parallel":
		cmd = filepath.Join(cfg.GANCmdHome, "deploy/build-parallel.sh")
	case "gogogo":
		cmd = filepath.Join(cfg.GANCmdHome, "deploy/gogogo.sh")
	case "deploy-docker", "docker-cluster-service-deploy":
		cmd = filepath.Join(cfg.GANCmdHome, "deploy/docker-cluster-service-deploy.sh")
	case "deploy-web", "web-release":
		cmd = filepath.Join(cfg.GANCmdHome, "deploy/web-release.sh")
	case "deploy":
		cmd = filepath.Join(cfg.GANCmdHome, "deploy/deploy.sh")
	case "docker-image-search":
		cmd = filepath.Join(cfg.GANCmdHome, "deploy/docker-image-search.sh")
	case "gan":
		cmd = filepath.Join(cfg.GANCmdHome, "gan.sh")
	default:
		return "", fmt.Errorf("Webhook信息之【do】不存在或错误")
	}

	// Action handling
	if req.Action != "" && req.Action != "default" {
		cmd += " --" + req.Action
	}

	// Common flags
	if req.Branch != "" {
		cmd += " --branch " + req.Branch
	}
	if matched, _ := regexp.MatchString(`(?i)^yes|^y`, req.SkipTest); matched {
		cmd += " --skiptest "
	}
	if matched, _ := regexp.MatchString(`(?i)^yes|^y`, req.Force); matched {
		cmd += " --force "
	}
	if matched, _ := regexp.MatchString(`(?i)^yes|^y`, req.Gray); matched {
		cmd += " --gray "
	}
	if req.Category != "" {
		cmd += " --category " + req.Category
	}
	if req.ReleaseVersion != "" {
		cmd += " --release-version " + req.ReleaseVersion
	}

	// Extra
	if req.Extra != "" {
		cmd += " " + req.Extra
	}

	// Projects
	if len(req.Projects) > 0 {
		cmd += " " + strings.Join(req.Projects, " ")
	}

	return cmd, nil
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

	// 获取客户端 IP
	clientIP := getClientIP(r)

	// 优先从 Cookie 读取 Token
	var token string
	cookie, err := r.Cookie("auth_token")
	if err == nil && cookie.Value != "" {
		token = cookie.Value
	} else {
		// 兼容旧方式: 从 Header 读取
		token = r.Header.Get("token")
	}

	user := r.Header.Get("user")
	sec := r.Header.Get("sec")

	if token == "" && (user == "" || sec == "") {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"Status": "Error", "Message": "请提供登录信息"})
		return
	}

	if token != "" {
		verifiedUser, err := s.authUserToken(token)
		if err != nil {
			log.Printf("[AUTH] Token 验证失败: ip=%s error=%v", clientIP, err)
			jsonResponse(w, http.StatusUnauthorized, map[string]string{"Status": "Error", "Message": "Token 无效或已过期，请重新登录"})
			return
		}
		user = verifiedUser
	} else {
		if _, err := s.authUserPW(user, sec); err != nil {
			log.Printf("[AUTH] 密码验证失败: user=%s ip=%s", user, clientIP)
			jsonResponse(w, http.StatusUnauthorized, map[string]string{"Status": "Error", "Message": "用户名或密码错误"})
			return
		}
	}

	var req RunReq
	if err := json.Unmarshal(rawBody, &req); err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"Status": "Error", "Message": "JSON解析失败"})
		return
	}

	userXingming, userEmail, err := s.getUserInfo(user)
	if err != nil {
		jsonResponse(w, http.StatusUnauthorized, map[string]string{"Status": "Error", "Message": err.Error()})
		return
	}

	if req.Do == "" {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"Status": "Error", "Message": "Webhook信息不存在或错误"})
		return
	}

	baseEnv := []string{
		"HOOK_USER_INFO_FROM=hook_hand",
		"HOOK_USER_NAME=" + user,
		"HOOK_USER_XINGMING=" + userXingming,
		"HOOK_USER_EMAIL=" + userEmail,
	}

	cmd, err := buildShellCmd(req, s.cfg)
	if err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"Status": "Error", "Message": err.Error()})
		return
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
