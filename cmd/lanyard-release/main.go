// Command lanyard-release is the maintainer's release helper:
//
//	lanyard-release keygen   -pub internal/update/pubkey.txt -key lanyard.key
//	lanyard-release manifest -version 1.2.3 -dir dist -github https://github.com/OWNER/REPO/releases/download/v1.2.3 -mirror https://updates.example.com/lanyard/1.2.3
//	lanyard-release sign     -in dist/manifest.json            (key + password from MINISIGN_SECRET_KEY / MINISIGN_PASSWORD)
//	lanyard-release verify   -in dist/manifest.json [-pub file]
//
// Keys and signatures are minisign-compatible: `minisign -Vm manifest.json -p
// pubkey.txt` verifies what this tool signs, and keys made with `minisign -G`
// work here too.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"aead.dev/minisign"
	"golang.org/x/term"

	"github.com/jinomee/lanyard/internal/brand"
	"github.com/jinomee/lanyard/internal/update"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "manifest":
		err = manifest(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	case "newer":
		// newer A B: exit status 0 if version A is newer than B, else 1.
		if len(os.Args) != 4 {
			usage()
		}
		if !update.Newer(os.Args[2], os.Args[3]) {
			os.Exit(1)
		}
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "lanyard-release:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: lanyard-release keygen|manifest|sign|verify [flags] | newer A B")
	os.Exit(2)
}

func readPassword(prompt string) (string, error) {
	if p, ok := os.LookupEnv("MINISIGN_PASSWORD"); ok {
		return p, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("set MINISIGN_PASSWORD or run in a terminal")
	}
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return string(b), err
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	pubPath := fs.String("pub", "internal/update/pubkey.txt", "public key output (commit this file)")
	keyPath := fs.String("key", brand.ID()+"-release.key", "encrypted private key output (NEVER commit; store as a GitHub secret)")
	_ = fs.Parse(args)
	if _, err := os.Stat(*keyPath); err == nil {
		return fmt.Errorf("%s already exists; refusing to overwrite", *keyPath)
	}
	pw, err := readPassword("Password for the new release key: ")
	if err != nil {
		return err
	}
	if len(pw) < 12 {
		return errors.New("use a password of at least 12 characters")
	}
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	enc, err := minisign.EncryptKey(pw, priv)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*keyPath, enc, 0o600); err != nil {
		return err
	}
	pubText, err := pub.MarshalText()
	if err != nil {
		return err
	}
	// pubText is already a complete minisign .pub file (comment line + key).
	if err := os.WriteFile(*pubPath, pubText, 0o644); err != nil { //nolint:gosec // public key
		return err
	}
	fmt.Printf("public key  → %s (commit it)\nprivate key → %s (add its contents as the MINISIGN_SECRET_KEY secret, the password as MINISIGN_PASSWORD, then delete or store it offline)\n", *pubPath, *keyPath)
	return nil
}

// kindOf derives the artifact kind from its file name.
func kindOf(name string) (osName, arch, kind string) {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "windows"):
		osName = "windows"
	case strings.Contains(n, "darwin"), strings.Contains(n, "macos"):
		osName = "darwin"
	case strings.Contains(n, "linux"):
		osName = "linux"
	}
	switch {
	case strings.Contains(n, "arm64"):
		arch = "arm64"
	case strings.Contains(n, "amd64"):
		arch = "amd64"
	}
	switch {
	case strings.Contains(n, "setup") || strings.Contains(n, "installer"):
		kind = "installer"
	case strings.Contains(n, "core"):
		kind = "core"
	default:
		kind = "portable"
	}
	return
}

func manifest(args []string) error {
	fs := flag.NewFlagSet("manifest", flag.ExitOnError)
	version := fs.String("version", "", "release version (no leading v)")
	dir := fs.String("dir", "dist", "directory with the release files")
	gh := fs.String("github", "", "base URL of the GitHub release downloads")
	mirror := fs.String("mirror", "", "base URL on the maintainer's server (optional)")
	notesURL := fs.String("notes-url", "", "release notes page")
	notesEn := fs.String("notes-en", "", "one-line English summary")
	notesZh := fs.String("notes-zh", "", "one-line Chinese summary")
	_ = fs.Parse(args)
	if *version == "" || *gh == "" {
		return errors.New("-version and -github are required")
	}
	entries, err := os.ReadDir(*dir)
	if err != nil {
		return err
	}
	m := update.Manifest{Product: brand.Name(), Version: strings.TrimPrefix(*version, "v"),
		Date: time.Now().UTC().Format("2006-01-02"), NotesURL: *notesURL, Notes: map[string]string{}}
	if *notesEn != "" {
		m.Notes["en"] = *notesEn
	}
	if *notesZh != "" {
		m.Notes["zh-CN"] = *notesZh
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || strings.HasPrefix(name, "manifest.json") || strings.HasSuffix(name, ".sha256") {
			continue
		}
		f, err := os.Open(filepath.Join(*dir, name))
		if err != nil {
			return err
		}
		h := sha256.New()
		n, err := io.Copy(h, f)
		_ = f.Close()
		if err != nil {
			return err
		}
		osName, arch, kind := kindOf(name)
		file := update.File{Name: name, OS: osName, Arch: arch, Kind: kind, Size: n, SHA256: hex.EncodeToString(h.Sum(nil)),
			URLs: []string{strings.TrimRight(*gh, "/") + "/" + name}}
		if *mirror != "" {
			file.URLs = append(file.URLs, strings.TrimRight(*mirror, "/")+"/"+name)
		}
		m.Files = append(m.Files, file)
	}
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Name < m.Files[j].Name })
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(*dir, "manifest.json")
	if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil { //nolint:gosec // public file
		return err
	}
	fmt.Printf("wrote %s (%d files)\n", path, len(m.Files))
	return nil
}

func loadPrivateKey() (minisign.PrivateKey, error) {
	text := os.Getenv("MINISIGN_SECRET_KEY")
	if text == "" {
		if p := os.Getenv("MINISIGN_SECRET_KEY_FILE"); p != "" {
			b, err := os.ReadFile(p)
			if err != nil {
				return minisign.PrivateKey{}, err
			}
			text = string(b)
		}
	}
	if text == "" {
		return minisign.PrivateKey{}, errors.New("MINISIGN_SECRET_KEY (or MINISIGN_SECRET_KEY_FILE) is not set")
	}
	raw := []byte(strings.TrimSpace(text) + "\n")
	if !minisign.IsEncrypted(raw) {
		var k minisign.PrivateKey
		return k, k.UnmarshalText(raw)
	}
	pw, err := readPassword("Release key password: ")
	if err != nil {
		return minisign.PrivateKey{}, err
	}
	return minisign.DecryptKey(pw, raw)
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	in := fs.String("in", "dist/manifest.json", "file to sign")
	_ = fs.Parse(args)
	key, err := loadPrivateKey()
	if err != nil {
		return err
	}
	body, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	what := filepath.Base(*in)
	var m update.Manifest
	if json.Unmarshal(body, &m) == nil && m.Version != "" {
		what = m.Version + " manifest"
	}
	sig := minisign.SignWithComments(key, body,
		fmt.Sprintf("%s %s, timestamp:%d", brand.Name(), what, time.Now().Unix()),
		fmt.Sprintf("signature from %s release key %X", brand.Name(), key.ID()))
	if err := os.WriteFile(*in+".minisig", sig, 0o644); err != nil { //nolint:gosec // public file
		return err
	}
	fmt.Println("wrote", *in+".minisig")
	return nil
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	in := fs.String("in", "dist/manifest.json", "manifest")
	pubPath := fs.String("pub", "", "public key file (default: the key embedded in this build)")
	_ = fs.Parse(args)
	if *pubPath != "" {
		b, err := os.ReadFile(*pubPath)
		if err != nil {
			return err
		}
		update.PublicKeyOverride = string(b)
	}
	pk, ok := update.PublicKey()
	if !ok {
		return errors.New("no public key configured")
	}
	body, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(*in + ".minisig")
	if err != nil {
		return err
	}
	m, err := update.Verify(pk, body, sig)
	if err != nil {
		return err
	}
	fmt.Printf("OK: %s %s, %d files\n", m.Product, m.Version, len(m.Files))
	return nil
}
