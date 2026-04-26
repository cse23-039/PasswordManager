package updater

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/minio/selfupdate"
)

const repoAPI = "https://api.github.com/repos/KagisoSetwaba/password-manager/releases/latest"

type Release struct {
	TagName string  `json:"tag_name"`
	HTMLURL string  `json:"html_url"`
	Assets  []Asset `json:"assets"`
}

type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// CheckForUpdate fetches the latest GitHub release and returns it if newer than current.
func CheckForUpdate(current string) (*Release, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodGet, repoAPI, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "PasswordManager/"+current)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github api returned %d", resp.StatusCode)
	}

	var release Release
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, err
	}

	latest := strings.TrimPrefix(release.TagName, "v")
	if isNewer(latest, strings.TrimPrefix(current, "v")) {
		return &release, nil
	}
	return nil, nil
}

// ApplyUpdate downloads the new binary for the current OS and replaces the running exe.
// progress is called with (bytesDownloaded, totalBytes) during the download.
func ApplyUpdate(release *Release, progress func(downloaded, total int64)) error {
	url, err := findAssetURL(release)
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var src io.Reader = resp.Body
	if progress != nil {
		src = &progressReader{r: resp.Body, total: resp.ContentLength, fn: progress}
	}

	return selfupdate.Apply(src, selfupdate.Options{})
}

func findAssetURL(release *Release) (string, error) {
	name := platformAssetName()
	for _, a := range release.Assets {
		if a.Name == name {
			return a.BrowserDownloadURL, nil
		}
	}
	return "", fmt.Errorf("no release asset found for %s", name)
}

func platformAssetName() string {
	switch runtime.GOOS {
	case "windows":
		return "password-manager.exe"
	case "darwin":
		return "password-manager-macos"
	default:
		return "password-manager-linux"
	}
}

type progressReader struct {
	r          io.Reader
	total      int64
	downloaded int64
	fn         func(downloaded, total int64)
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.downloaded += int64(n)
	p.fn(p.downloaded, p.total)
	return n, err
}

func isNewer(candidate, base string) bool {
	c := parseSemver(candidate)
	b := parseSemver(base)
	for i := range b {
		if c[i] != b[i] {
			return c[i] > b[i]
		}
	}
	return false
}

func parseSemver(v string) [3]int {
	var out [3]int
	parts := strings.SplitN(v, ".", 3)
	for i, p := range parts {
		if i >= 3 {
			break
		}
		n, _ := strconv.Atoi(p)
		out[i] = n
	}
	return out
}
