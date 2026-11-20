package database

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PgConfig contient les paramètres de connexion extraits de DATABASE_URL.
type PgConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	Database string
}

// ParseDatabaseURL décode une URL PostgreSQL (ex: postgresql://user:pass@host:5432/db).
func ParseDatabaseURL(rawURL string) PgConfig {
	cfg := PgConfig{
		Host:     "timescaledb",
		Port:     "5432",
		User:     "aegis_user",
		Password: "aegis_dev_password",
		Database: "aegis_db",
	}
	if rawURL == "" {
		return cfg
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return cfg
	}
	if u.Hostname() != "" {
		cfg.Host = u.Hostname()
	}
	if u.Port() != "" {
		cfg.Port = u.Port()
	}
	if u.User != nil {
		if u.User.Username() != "" {
			cfg.User = u.User.Username()
		}
		if pass, ok := u.User.Password(); ok {
			cfg.Password = pass
		}
	}
	dbName := strings.TrimPrefix(u.Path, "/")
	if dbName != "" {
		cfg.Database = dbName
	}
	return cfg
}

// PgRow représente une ligne de résultat SQL sous forme de map colonne -> valeur texte.
type PgRow map[string]string

// String retourne la valeur d'une colonne ou une valeur par défaut si NULL/absente.
func (r PgRow) String(col string) string {
	if r == nil {
		return ""
	}
	return r[col]
}

// Int retourne la valeur entière d'une colonne.
func (r PgRow) Int(col string) int {
	val, err := strconv.Atoi(strings.TrimSpace(r.String(col)))
	if err != nil {
		f, errF := strconv.ParseFloat(strings.TrimSpace(r.String(col)), 64)
		if errF == nil {
			return int(f)
		}
		return 0
	}
	return val
}

// Float retourne la valeur flottante (float64) d'une colonne.
func (r PgRow) Float(col string) float64 {
	val, err := strconv.ParseFloat(strings.TrimSpace(r.String(col)), 64)
	if err != nil {
		return 0.0
	}
	return val
}

// Bool retourne la valeur booléenne d'une colonne PostgreSQL ('t', 'true', '1').
func (r PgRow) Bool(col string) bool {
	s := strings.ToLower(strings.TrimSpace(r.String(col)))
	return s == "t" || s == "true" || s == "1"
}

// PgClient gère un pool léger de connexions TCP PostgreSQL thread-safe.
type PgClient struct {
	cfg  PgConfig
	mu   sync.Mutex
	conn net.Conn
}

// NewPgClient initialise un client PostgreSQL.
func NewPgClient(cfg PgConfig) *PgClient {
	return &PgClient{cfg: cfg}
}

// QuoteLiteral échappe proprement une chaîne de caractères pour éviter toute injection SQL
// dans le protocole Simple Query PostgreSQL.
func QuoteLiteral(s string) string {
	clean := strings.ReplaceAll(s, "\x00", "")
	escaped := strings.ReplaceAll(clean, "'", "''")
	return "'" + escaped + "'"
}

// ensureConnected ouvre et authentifie une connexion TCP vers PostgreSQL si nécessaire.
func (c *PgClient) ensureConnected() error {
	if c.conn != nil {
		return nil
	}
	addr := net.JoinHostPort(c.cfg.Host, c.cfg.Port)
	conn, err := net.DialTimeout("tcp", addr, 4*time.Second)
	if err != nil {
		return fmt.Errorf("dial postgres %s: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	if err := c.handshake(conn); err != nil {
		_ = conn.Close()
		return err
	}
	_ = conn.SetDeadline(time.Time{})
	c.conn = conn
	return nil
}

// closeLocked ferme la connexion courante.
func (c *PgClient) closeLocked() {
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
}

// Query exécute une requête SQL et renvoie toutes les lignes du dernier ResultSet.
func (c *PgClient) Query(sqlQuery string) ([]PgRow, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for attempt := 0; attempt < 2; attempt++ {
		if err := c.ensureConnected(); err != nil {
			return nil, err
		}
		rows, err := c.execSimpleQueryLocked(sqlQuery)
		if err != nil {
			if isNetworkError(err) && attempt == 0 {
				c.closeLocked()
				continue
			}
			return nil, err
		}
		return rows, nil
	}
	return nil, errors.New("échec requête PostgreSQL après reconnexion")
}

// QueryRow exécute une requête SQL et renvoie la première ligne (ou une ligne vide).
func (c *PgClient) QueryRow(sqlQuery string) (PgRow, error) {
	rows, err := c.Query(sqlQuery)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return PgRow{}, nil
	}
	return rows[0], nil
}

// Exec exécute une commande SQL (INSERT, UPDATE, DELETE, CREATE, ALTER).
func (c *PgClient) Exec(sqlQuery string) error {
	_, err := c.Query(sqlQuery)
	return err
}

func isNetworkError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr)
}

func (c *PgClient) handshake(conn net.Conn) error {
	// 1. Envoi du paquet StartupMessage (Protocole 3.0 = 196608)
	var body bytes.Buffer
	body.WriteString("user\x00")
	body.WriteString(c.cfg.User + "\x00")
	body.WriteString("database\x00")
	body.WriteString(c.cfg.Database + "\x00")
	body.WriteString("client_encoding\x00UTF8\x00")
	body.WriteString("\x00")

	totalLen := int32(4 + 4 + body.Len())
	var packet bytes.Buffer
	_ = binary.Write(&packet, binary.BigEndian, totalLen)
	_ = binary.Write(&packet, binary.BigEndian, int32(196608))
	packet.Write(body.Bytes())

	if _, err := conn.Write(packet.Bytes()); err != nil {
		return fmt.Errorf("write startup message: %w", err)
	}

	for {
		msgType, msgBody, err := readWireMessage(conn)
		if err != nil {
			return fmt.Errorf("read handshake message: %w", err)
		}
		switch msgType {
		case 'R':
			if len(msgBody) < 4 {
				return errors.New("message d'authentification invalide")
			}
			authCode := binary.BigEndian.Uint32(msgBody[0:4])
			switch authCode {
			case 0:
				// Ok
			case 3:
				// Cleartext
				if err := sendPasswordMessage(conn, c.cfg.Password); err != nil {
					return err
				}
			case 5:
				// MD5
				if len(msgBody) < 8 {
					return errors.New("salt MD5 manquant")
				}
				salt := msgBody[4:8]
				md5Pass := computePgMD5Password(c.cfg.User, c.cfg.Password, salt)
				if err := sendPasswordMessage(conn, md5Pass); err != nil {
					return err
				}
			case 10:
				// SCRAM-SHA-256
				if err := c.handleSCRAMAuth(conn, msgBody[4:]); err != nil {
					return fmt.Errorf("scram auth: %w", err)
				}
			default:
				return fmt.Errorf("méthode d'authentification PostgreSQL non supportée: %d", authCode)
			}
		case 'E':
			return fmt.Errorf("erreur postgres lors du handshake: %s", parseErrorResponse(msgBody))
		case 'Z':
			return nil
		case 'K', 'S', 'N':
			// Ignorer (BackendKeyData, ParameterStatus, Notice)
		}
	}
}

func (c *PgClient) handleSCRAMAuth(conn net.Conn, mechanisms []byte) error {
	clientNonce := make([]byte, 18)
	if _, err := rand.Read(clientNonce); err != nil {
		return err
	}
	cNonce := base64.StdEncoding.EncodeToString(clientNonce)
	clientFirstBare := "n=" + c.cfg.User + ",r=" + cNonce
	clientFirstMsg := "n,," + clientFirstBare

	var body bytes.Buffer
	body.WriteString("SCRAM-SHA-256\x00")
	_ = binary.Write(&body, binary.BigEndian, int32(len(clientFirstMsg)))
	body.WriteString(clientFirstMsg)

	packet := prependType('p', body.Bytes())
	if _, err := conn.Write(packet); err != nil {
		return err
	}

	msgType, serverFirstMsg, err := readWireMessage(conn)
	if err != nil {
		return fmt.Errorf("lecture SASLContinue: %w", err)
	}
	if msgType == 'E' {
		return fmt.Errorf("reçu 'E' (erreur postgres): %s", parseErrorResponse(serverFirstMsg))
	}
	if msgType != 'R' {
		return fmt.Errorf("attente de R (AuthenticationSASLContinue), reçu '%c'", msgType)
	}
	if len(serverFirstMsg) < 4 || binary.BigEndian.Uint32(serverFirstMsg[0:4]) != 11 {
		return errors.New("sasl continue invalide")
	}
	serverFirstPayload := string(serverFirstMsg[4:])

	parts := strings.Split(serverFirstPayload, ",")
	var sNonce, saltB64 string
	var iterations int
	for _, p := range parts {
		if strings.HasPrefix(p, "r=") {
			sNonce = strings.TrimPrefix(p, "r=")
		} else if strings.HasPrefix(p, "s=") {
			saltB64 = strings.TrimPrefix(p, "s=")
		} else if strings.HasPrefix(p, "i=") {
			iterations, _ = strconv.Atoi(strings.TrimPrefix(p, "i="))
		}
	}
	if !strings.HasPrefix(sNonce, cNonce) || saltB64 == "" || iterations == 0 {
		return errors.New("réponse SCRAM serveur invalide")
	}

	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return err
	}

	saltedPassword := pbkdf2HmacSha256([]byte(c.cfg.Password), salt, iterations, 32)
	clientKey := hmacSha256(saltedPassword, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)

	authMsg := clientFirstBare + "," + serverFirstPayload + ",c=biws,r=" + sNonce
	clientSig := hmacSha256(storedKey[:], []byte(authMsg))

	clientProof := make([]byte, len(clientKey))
	for i := range clientKey {
		clientProof[i] = clientKey[i] ^ clientSig[i]
	}

	clientFinalMsg := "c=biws,r=" + sNonce + ",p=" + base64.StdEncoding.EncodeToString(clientProof)

	finalPacket := prependType('p', []byte(clientFinalMsg))
	if _, err := conn.Write(finalPacket); err != nil {
		return err
	}

	msgType, saslFinal, err := readWireMessage(conn)
	if err != nil || msgType != 'R' {
		return fmt.Errorf("attente SASLFinal, reçu '%c': %w", msgType, err)
	}
	if len(saslFinal) < 4 || binary.BigEndian.Uint32(saslFinal[0:4]) != 12 {
		return errors.New("authentification SCRAM-SHA-256 refusée par le serveur")
	}

	return nil
}

func (c *PgClient) execSimpleQueryLocked(sql string) ([]PgRow, error) {
	_ = c.conn.SetDeadline(time.Now().Add(12 * time.Second))
	defer func() {
		if c.conn != nil {
			_ = c.conn.SetDeadline(time.Time{})
		}
	}()

	packet := prependType('Q', append([]byte(sql), 0x00))
	if _, err := c.conn.Write(packet); err != nil {
		return nil, fmt.Errorf("envoi simple query: %w", err)
	}

	var columns []string
	var rows []PgRow

	for {
		msgType, msgBody, err := readWireMessage(c.conn)
		if err != nil {
			return nil, fmt.Errorf("lecture réponse query: %w", err)
		}
		switch msgType {
		case 'T':
			// RowDescription
			if len(msgBody) < 2 {
				continue
			}
			numFields := int(binary.BigEndian.Uint16(msgBody[0:2]))
			columns = make([]string, 0, numFields)
			offset := 2
			for i := 0; i < numFields && offset < len(msgBody); i++ {
				nullIdx := bytes.IndexByte(msgBody[offset:], 0x00)
				if nullIdx == -1 {
					break
				}
				colName := string(msgBody[offset : offset+nullIdx])
				columns = append(columns, colName)
				offset += nullIdx + 1 + 18
			}
		case 'D':
			// DataRow
			if len(msgBody) < 2 {
				continue
			}
			numCols := int(binary.BigEndian.Uint16(msgBody[0:2]))
			row := make(PgRow, numCols)
			offset := 2
			for i := 0; i < numCols && offset < len(msgBody); i++ {
				if offset+4 > len(msgBody) {
					break
				}
				colLen := int(int32(binary.BigEndian.Uint32(msgBody[offset : offset+4])))
				offset += 4
				colName := fmt.Sprintf("col_%d", i)
				if i < len(columns) {
					colName = columns[i]
				}
				if colLen == -1 {
					row[colName] = ""
				} else if offset+colLen <= len(msgBody) {
					row[colName] = string(msgBody[offset : offset+colLen])
					offset += colLen
				}
			}
			rows = append(rows, row)
		case 'C':
			// CommandComplete
		case 'E':
			return nil, fmt.Errorf("erreur postgres: %s", parseErrorResponse(msgBody))
		case 'Z':
			// ReadyForQuery
			return rows, nil
		case 'N', 'A', 'I':
			// NoticeResponse, NotificationResponse, EmptyQueryResponse
		}
	}
}

func readWireMessage(r io.Reader) (byte, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}
	msgType := header[0]
	msgLen := int(binary.BigEndian.Uint32(header[1:5]))
	if msgLen < 4 {
		return 0, nil, errors.New("longueur de message PostgreSQL invalide")
	}
	bodyLen := msgLen - 4
	body := make([]byte, bodyLen)
	if bodyLen > 0 {
		if _, err := io.ReadFull(r, body); err != nil {
			return 0, nil, err
		}
	}
	return msgType, body, nil
}

func prependType(msgType byte, body []byte) []byte {
	totalLen := int32(4 + len(body))
	res := make([]byte, 1+4+len(body))
	res[0] = msgType
	binary.BigEndian.PutUint32(res[1:5], uint32(totalLen))
	copy(res[5:], body)
	return res
}

func sendPasswordMessage(w io.Writer, pass string) error {
	packet := prependType('p', append([]byte(pass), 0x00))
	_, err := w.Write(packet)
	return err
}

func computePgMD5Password(user, password string, salt []byte) string {
	h1 := md5.Sum([]byte(password + user))
	h1Hex := hex.EncodeToString(h1[:])
	h2 := md5.New()
	h2.Write([]byte(h1Hex))
	h2.Write(salt)
	return "md5" + hex.EncodeToString(h2.Sum(nil))
}

func hmacSha256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func pbkdf2HmacSha256(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen
	var result []byte

	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		var blockBuf [4]byte
		binary.BigEndian.PutUint32(blockBuf[:], uint32(block))
		prf.Write(blockBuf[:])
		u := prf.Sum(nil)
		ui := make([]byte, len(u))
		copy(ui, u)

		for i := 1; i < iter; i++ {
			prf.Reset()
			prf.Write(ui)
			ui = prf.Sum(nil)
			for j := range u {
				u[j] ^= ui[j]
			}
		}
		result = append(result, u...)
	}
	return result[:keyLen]
}

func parseErrorResponse(body []byte) string {
	var msgs []string
	offset := 0
	for offset < len(body) {
		field := body[offset]
		if field == 0 {
			break
		}
		offset++
		nullIdx := bytes.IndexByte(body[offset:], 0x00)
		if nullIdx == -1 {
			break
		}
		val := string(body[offset : offset+nullIdx])
		if field == 'M' || field == 'D' || field == 'C' {
			msgs = append(msgs, val)
		}
		offset += nullIdx + 1
	}
	if len(msgs) == 0 {
		return "erreur inconnue"
	}
	return strings.Join(msgs, " - ")
}
