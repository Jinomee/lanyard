// Package i18n holds every user-facing string of LANyard (GUI and core) in
// locales/*.json. The core sends message keys plus parameters; clients render
// them with these catalogs, so all languages stay in one place.
//
// Placeholders are written {name}. {app} is always available and expands to
// the product name in that language.
package i18n

import (
	"embed"
	"encoding/json"
	"path"
	"sort"
	"strings"

	"github.com/jinomee/lanyard/internal/brand"
)

//go:embed locales/*.json
var files embed.FS

// Default is the fallback language.
const Default = "en"

var catalogs = load()

func load() map[string]map[string]string {
	out := map[string]map[string]string{}
	entries, err := files.ReadDir("locales")
	if err != nil {
		panic(err)
	}
	for _, e := range entries {
		b, err := files.ReadFile(path.Join("locales", e.Name()))
		if err != nil {
			panic(err)
		}
		m := map[string]string{}
		if err := json.Unmarshal(b, &m); err != nil {
			panic("i18n: " + e.Name() + ": " + err.Error())
		}
		out[strings.TrimSuffix(e.Name(), ".json")] = m
	}
	return out
}

// Languages returns the available language tags, sorted.
func Languages() []string {
	var ls []string
	for l := range catalogs {
		ls = append(ls, l)
	}
	sort.Strings(ls)
	return ls
}

// Match maps an OS/browser language tag ("zh-Hans-CN", "en_US") to a catalog.
func Match(tag string) string {
	t := strings.ToLower(strings.ReplaceAll(tag, "_", "-"))
	if strings.HasPrefix(t, "zh") {
		return "zh-CN"
	}
	if _, ok := catalogs[tag]; ok {
		return tag
	}
	return Default
}

// Catalog returns a copy of a language's strings with {app} filled in.
func Catalog(lang string) map[string]string {
	lang = Match(lang)
	out := make(map[string]string, len(catalogs[Default]))
	for k, v := range catalogs[Default] {
		out[k] = v
	}
	for k, v := range catalogs[lang] {
		out[k] = v
	}
	app := AppName(lang)
	for k, v := range out {
		out[k] = strings.ReplaceAll(v, "{app}", app)
	}
	return out
}

// AppName returns the product name for a language.
func AppName(lang string) string {
	if Match(lang) == "zh-CN" && brand.Get().NameZh != "" {
		return brand.Get().NameZh
	}
	return brand.Name()
}

// T renders key in lang with params (name, value pairs). Missing keys render
// as the key itself so a gap is visible rather than silent.
func T(lang, key string, params ...string) string {
	lang = Match(lang)
	s, ok := catalogs[lang][key]
	if !ok {
		s, ok = catalogs[Default][key]
	}
	if !ok {
		return key
	}
	s = strings.ReplaceAll(s, "{app}", AppName(lang))
	for i := 0; i+1 < len(params); i += 2 {
		s = strings.ReplaceAll(s, "{"+params[i]+"}", params[i+1])
	}
	return s
}

// Keys returns all keys of a language catalog (for tests).
func Keys(lang string) []string {
	var ks []string
	for k := range catalogs[lang] {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
