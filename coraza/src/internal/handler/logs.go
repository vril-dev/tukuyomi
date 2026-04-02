package handler

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

var (
	logDirCoraza          = "logs/coraza"
	logDirNginx           = "logs/nginx"
	logDirOpenrestyLegacy = "logs/openresty"

	logFiles = map[string]string{
		"waf":    filepath.Join(logDirCoraza, "waf-events.ndjson"),
		"accerr": filepath.Join(logDirNginx, "access-error.ndjson"),
		"intr":   filepath.Join(logDirNginx, "interesting.ndjson"),
	}

	readChunkSize   = int64(64 * 1024)
	maxLinesPerRead = 200
	maxBytesPerRead = int64(512 * 1024)

	defaultStatsScanLines  = 5000
	maxStatsScanLines      = 50000
	defaultStatsRangeHours = 24
	maxStatsRangeHours     = 14 * 24
	statsTopN              = 5
)

type logLine map[string]any

type lineIndex struct {
	Offsets []int64
	Size    int64
	ModTime time.Time
}

var (
	idxMu  sync.RWMutex
	fileIx = map[string]*lineIndex{}
)

type readResp struct {
	Lines      []logLine `json:"lines"`
	NextCursor *int64    `json:"next_cursor,omitempty"`
	PageStart  *int64    `json:"page_start,omitempty"`
	PageEnd    *int64    `json:"page_end,omitempty"`
	HasMore    bool      `json:"has_more"`
	HasPrev    bool      `json:"has_prev"`
	HasNext    bool      `json:"has_next"`
}

type statsBucket struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

type statsSeriesPoint struct {
	BucketStart string `json:"bucket_start"`
	Count       int    `json:"count"`
}

type wafBlockStats struct {
	Last1h          int                `json:"last_1h"`
	Last24h         int                `json:"last_24h"`
	TotalInScan     int                `json:"total_in_scan"`
	TopRuleIDs24h   []statsBucket      `json:"top_rule_ids_24h"`
	TopPaths24h     []statsBucket      `json:"top_paths_24h"`
	TopCountries24h []statsBucket      `json:"top_countries_24h"`
	SeriesHourly    []statsSeriesPoint `json:"series_hourly"`
}

type logsStatsResp struct {
	GeneratedAt     string        `json:"generated_at"`
	ScannedLines    int           `json:"scanned_lines"`
	RangeHours      int           `json:"range_hours"`
	OldestScannedTS string        `json:"oldest_scanned_ts,omitempty"`
	NewestScannedTS string        `json:"newest_scanned_ts,omitempty"`
	WAFBlock        wafBlockStats `json:"waf_block"`
}

func LogsRead(c *gin.Context) {
	src := c.Query("src")
	path, ok := logFiles[src]
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid src"})
		return
	}
	path = resolveLogPath(src, path)

	tail := clampInt(mustAtoiDefault(c.Query("tail"), 30), 1, maxLinesPerRead)
	dir := c.DefaultQuery("dir", "")
	var cursor *int64
	if v := c.Query("cursor"); v != "" {
		off := mustAtoi64Default(v, 0)
		cursor = &off
	}
	countryFilter := normalizeCountryFilter(c.Query("country"))

	var (
		lines            []logLine
		nextCur          *int64
		hasPrev, hasNext bool
		err              error
	)
	if src == "waf" {
		if store := getLogsStatsStore(); store != nil {
			lines, nextCur, hasPrev, hasNext, err = store.ReadWAFLogs(path, tail, cursor, dir, countryFilter)
		} else {
			lines, nextCur, hasPrev, hasNext, err = readByLine(path, tail, cursor, dir)
		}
	} else {
		lines, nextCur, hasPrev, hasNext, err = readByLine(path, tail, cursor, dir)
	}
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c.JSON(http.StatusOK, readResp{Lines: nil, NextCursor: nil, HasMore: false})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	normalizeCountryInLines(lines)
	pageStart, pageEnd := computePageBounds(dir, nextCur, len(lines))
	lines = filterLinesByCountry(lines, countryFilter)

	resp := readResp{
		Lines:      lines,
		NextCursor: nextCur,
		PageStart:  pageStart,
		PageEnd:    pageEnd,
		HasPrev:    hasPrev,
		HasNext:    hasNext,
	}

	if dir == "prev" {
		resp.HasMore = hasPrev
	} else {
		resp.HasMore = hasNext
	}

	c.JSON(http.StatusOK, resp)
}

func LogsDownload(c *gin.Context) {
	src := c.Query("src")
	path, ok := logFiles[src]
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid src"})
		return
	}
	path = resolveLogPath(src, path)

	fromStr := c.Query("from")
	toStr := c.Query("to")
	var (
		from time.Time
		to   time.Time
		err  error
	)

	if fromStr != "" {
		from, err = time.Parse(time.RFC3339, fromStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid from"})
			return
		}
	}

	if toStr != "" {
		to, err = time.Parse(time.RFC3339, toStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid to"})
			return
		}
	}

	if toStr == "" {
		to = time.Now().Add(1 * time.Second)
	}
	countryFilter := normalizeCountryFilter(c.Query("country"))

	c.Header("Content-Type", "application/x-ndjson")
	filename := fmt.Sprintf("%s-%s.ndjson.gz", src, time.Now().Format("20060102"))
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	c.Header("Content-Encoding", "gzip")

	gw := gzip.NewWriter(c.Writer)
	defer gw.Close()

	if src == "waf" {
		if store := getLogsStatsStore(); store != nil {
			if err := store.DownloadWAFLogs(path, gw, from, to, countryFilter); err != nil {
				c.Status(http.StatusInternalServerError)
			}
			return
		}
	}

	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	br := bufio.NewReaderSize(f, 64*1024)
	for {
		b, err := br.ReadBytes('\n')
		if len(b) > 0 {
			var m map[string]any
			if json.Unmarshal(b, &m) == nil {
				if ts, ok := m["ts"].(string); ok && tsInRange(ts, from, to) && countryMatchesFilter(m["country"], countryFilter) {
					if _, err := gw.Write(b); err != nil {
						break
					}
				}
			}
		}

		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			break
		}
	}
}

func LogsStats(c *gin.Context) {
	path, ok := logFiles["waf"]
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "waf log source is not configured"})
		return
	}
	path = resolveLogPath("waf", path)

	rangeHours := clampInt(mustAtoiDefault(c.Query("hours"), defaultStatsRangeHours), 1, maxStatsRangeHours)
	now := time.Now().UTC()
	if store := getLogsStatsStore(); store != nil {
		resp, err := store.BuildLogsStats(path, rangeHours, now)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, resp)
		return
	}

	scan := clampInt(mustAtoiDefault(c.Query("scan"), defaultStatsScanLines), 1, maxStatsScanLines)
	seriesStart, seriesEnd := statsHourlyRange(now, rangeHours)

	lines, _, _, _, err := readByLine(path, scan, nil, "")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c.JSON(http.StatusOK, logsStatsResp{
				GeneratedAt:  now.Format(time.RFC3339Nano),
				ScannedLines: 0,
				RangeHours:   rangeHours,
				WAFBlock: wafBlockStats{
					TopRuleIDs24h:   []statsBucket{},
					TopPaths24h:     []statsBucket{},
					TopCountries24h: []statsBucket{},
					SeriesHourly:    buildHourlySeries(seriesStart, seriesEnd, map[int64]int{}),
				},
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	since1h := now.Add(-1 * time.Hour)
	since24h := now.Add(-24 * time.Hour)

	ruleCounts24h := map[string]int{}
	pathCounts24h := map[string]int{}
	countryCounts24h := map[string]int{}
	seriesCounts := map[int64]int{}

	stats := wafBlockStats{
		TopRuleIDs24h:   []statsBucket{},
		TopPaths24h:     []statsBucket{},
		TopCountries24h: []statsBucket{},
		SeriesHourly:    []statsSeriesPoint{},
	}
	var oldestScannedTS time.Time
	var newestScannedTS time.Time
	haveScannedTS := false

	for _, line := range lines {
		if strings.TrimSpace(logFieldString(line["event"])) != "waf_block" {
			continue
		}

		stats.TotalInScan++

		ts, ok := parseLogTS(line["ts"])
		if !ok {
			continue
		}
		ts = ts.UTC()
		if !haveScannedTS || ts.Before(oldestScannedTS) {
			oldestScannedTS = ts
		}
		if !haveScannedTS || ts.After(newestScannedTS) {
			newestScannedTS = ts
		}
		haveScannedTS = true

		if !ts.Before(since1h) {
			stats.Last1h++
		}
		if ts.Before(since24h) {
			if !ts.Before(seriesStart) && ts.Before(seriesEnd) {
				hourBucket := ts.Truncate(time.Hour).Unix()
				seriesCounts[hourBucket]++
			}
			continue
		}

		stats.Last24h++

		ruleID := normalizeStatsRuleID(line["rule_id"])
		pathKey := normalizeStatsPath(line["path"])
		country := normalizeCountryFromAny(line["country"])

		ruleCounts24h[ruleID]++
		pathCounts24h[pathKey]++
		countryCounts24h[country]++

		if !ts.Before(seriesStart) && ts.Before(seriesEnd) {
			hourBucket := ts.Truncate(time.Hour).Unix()
			seriesCounts[hourBucket]++
		}
	}

	stats.TopRuleIDs24h = topBuckets(ruleCounts24h, statsTopN)
	stats.TopPaths24h = topBuckets(pathCounts24h, statsTopN)
	stats.TopCountries24h = topBuckets(countryCounts24h, statsTopN)
	stats.SeriesHourly = buildHourlySeries(seriesStart, seriesEnd, seriesCounts)

	resp := logsStatsResp{
		GeneratedAt:  now.Format(time.RFC3339Nano),
		ScannedLines: len(lines),
		RangeHours:   rangeHours,
		WAFBlock:     stats,
	}
	if haveScannedTS {
		resp.OldestScannedTS = oldestScannedTS.Format(time.RFC3339Nano)
		resp.NewestScannedTS = newestScannedTS.Format(time.RFC3339Nano)
	}

	c.JSON(http.StatusOK, resp)
}

func parseLogTS(raw any) (time.Time, bool) {
	ts := strings.TrimSpace(logFieldString(raw))
	if ts == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		return t, true
	}
	if t, err := time.Parse(time.RFC3339, ts); err == nil {
		return t, true
	}
	return time.Time{}, false
}

func logFieldString(raw any) string {
	if raw == nil {
		return ""
	}
	switch v := raw.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case int:
		return strconv.Itoa(v)
	case int32:
		return strconv.FormatInt(int64(v), 10)
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		if v == float64(int64(v)) {
			return strconv.FormatInt(int64(v), 10)
		}
		return strconv.FormatFloat(v, 'f', -1, 64)
	default:
		return fmt.Sprintf("%v", raw)
	}
}

func normalizeStatsRuleID(raw any) string {
	v := strings.TrimSpace(logFieldString(raw))
	if v == "" || v == "<nil>" {
		return "UNKNOWN"
	}
	return v
}

func normalizeStatsPath(raw any) string {
	v := strings.TrimSpace(logFieldString(raw))
	if v == "" || v == "<nil>" {
		return "/"
	}
	if !strings.HasPrefix(v, "/") {
		return "/"
	}
	return v
}

func topBuckets(in map[string]int, n int) []statsBucket {
	if len(in) == 0 || n <= 0 {
		return []statsBucket{}
	}
	out := make([]statsBucket, 0, len(in))
	for k, c := range in {
		out = append(out, statsBucket{Key: k, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Key < out[j].Key
		}
		return out[i].Count > out[j].Count
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func statsHourlyRange(now time.Time, rangeHours int) (time.Time, time.Time) {
	end := now.UTC().Truncate(time.Hour).Add(time.Hour)
	start := end.Add(-time.Duration(rangeHours) * time.Hour)
	return start, end
}

func buildHourlySeries(start, end time.Time, counts map[int64]int) []statsSeriesPoint {
	if !start.Before(end) {
		return []statsSeriesPoint{}
	}
	out := make([]statsSeriesPoint, 0, int(end.Sub(start)/time.Hour))
	for t := start; t.Before(end); t = t.Add(time.Hour) {
		out = append(out, statsSeriesPoint{
			BucketStart: t.Format(time.RFC3339),
			Count:       counts[t.Unix()],
		})
	}
	return out
}

func resolveLogPath(src, current string) string {
	if src == "waf" || current == "" {
		return current
	}
	if _, err := os.Stat(current); err == nil {
		return current
	}
	legacy := strings.Replace(current, logDirNginx+"/", logDirOpenrestyLegacy+"/", 1)
	if _, err := os.Stat(legacy); err == nil {
		return legacy
	}
	return current
}

func buildOrUpdateIndex(path string) (*lineIndex, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	idxMu.Lock()
	defer idxMu.Unlock()

	li := fileIx[path]
	if li == nil || fi.Size() < li.Size || fi.ModTime().After(li.ModTime) {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()

		br := bufio.NewReaderSize(f, 128*1024)
		var offs []int64
		offs = append(offs, 0)
		var pos int64
		for {
			b, err := br.ReadBytes('\n')
			if len(b) > 0 {
				pos += int64(len(b))
				offs = append(offs, pos)
			}

			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}

				return nil, err
			}
		}

		li = &lineIndex{Offsets: offs, Size: fi.Size(), ModTime: fi.ModTime()}
		fileIx[path] = li

		return li, nil
	}

	if fi.Size() > li.Size {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()

		if _, err := f.Seek(li.Size, io.SeekStart); err != nil {
			return nil, err
		}

		br := bufio.NewReaderSize(f, 128*1024)
		pos := li.Size
		for {
			b, err := br.ReadBytes('\n')
			if len(b) > 0 {
				pos += int64(len(b))
				li.Offsets = append(li.Offsets, pos)
			}

			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}

				return nil, err
			}
		}

		li.Size = fi.Size()
		li.ModTime = fi.ModTime()
	}

	return li, nil
}

func readByLine(path string, tail int, cursor *int64, dir string) ([]logLine, *int64, bool, bool, error) {
	li, err := buildOrUpdateIndex(path)
	if err != nil {
		return nil, nil, false, false, err
	}

	totalMarks := len(li.Offsets)
	if totalMarks == 0 {
		z := int64(0)
		return nil, &z, false, false, nil
	}
	totalLines := totalMarks - 1

	var cur int
	if cursor == nil {
		if tail > totalLines {
			cur = 0
		} else {
			cur = totalLines - tail
		}
	} else {
		cur = int(*cursor)
		if cur < 0 {
			cur = 0
		}
		if cur > totalLines {
			cur = totalLines
		}
	}

	var start, end int
	switch dir {
	case "prev":
		start, end = maxInt(cur-tail, 0), cur
	case "next", "":
		start, end = cur, minInt(cur+tail, totalLines)
	default:
		return nil, nil, false, false, fmt.Errorf("invalid dir")
	}

	if start >= end {
		nextCur := int64(end)
		return []logLine{}, &nextCur, start > 0, end < totalLines, nil
	}

	byteStart := li.Offsets[start]
	byteEnd := li.Offsets[end]
	size := byteEnd - byteStart

	f, err := os.Open(path)
	if err != nil {
		return nil, nil, false, false, err
	}
	defer f.Close()

	if _, err := f.Seek(byteStart, io.SeekStart); err != nil {
		return nil, nil, false, false, err
	}

	buf := make([]byte, size)
	if _, err := io.ReadFull(f, buf); err != nil {
		return nil, nil, false, false, err
	}

	br := bufio.NewReaderSize(bytes.NewReader(buf), 64*1024)
	out := make([]logLine, 0, tail)
	for {
		b, err := br.ReadBytes('\n')
		if len(b) > 0 {
			var m map[string]any
			if json.Unmarshal(trimLastNewline(b), &m) == nil {
				out = append(out, m)
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, nil, false, false, err
		}
	}

	var nextCur int64
	if dir == "prev" {
		nextCur = int64(start)
	} else {
		nextCur = int64(end)
	}
	hasPrev := start > 0
	hasNext := end < totalLines
	return out, &nextCur, hasPrev, hasNext, nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}

	if v > hi {
		return hi
	}

	return v
}

func clamp64(v, lo, hi int64) int64 {
	if v < lo {
		return lo
	}

	if v > hi {
		return hi
	}

	return v
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}

	return b
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}

	return b
}

func mustAtoiDefault(s string, d int) int {
	if s == "" {
		return d
	}

	i, _ := strconv.Atoi(s)
	if i == 0 {
		return d
	}

	return i
}

func mustAtoi64Default(s string, d int64) int64 {
	if s == "" {
		return d
	}

	i, _ := strconv.ParseInt(s, 10, 64)
	if i == 0 {
		return d
	}

	return i
}

func tsInRange(ts string, from, to time.Time) bool {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return false
	}

	if !from.IsZero() && t.Before(from) {
		return false
	}

	if !to.IsZero() && !t.Before(to) {
		return false
	}

	return true
}

func filterLinesByCountry(lines []logLine, filter string) []logLine {
	if filter == "" {
		return lines
	}

	out := make([]logLine, 0, len(lines))
	for _, line := range lines {
		if countryMatchesFilter(line["country"], filter) {
			out = append(out, line)
		}
	}

	return out
}

func normalizeCountryInLines(lines []logLine) {
	for _, line := range lines {
		line["country"] = normalizeCountryFromAny(line["country"])
	}
}

func computePageBounds(dir string, nextCur *int64, lineCount int) (*int64, *int64) {
	if nextCur == nil {
		return nil, nil
	}

	n := int64(lineCount)
	switch dir {
	case "prev":
		start := *nextCur
		end := start + n
		return &start, &end
	default:
		end := *nextCur
		start := max64(0, end-n)
		return &start, &end
	}
}

func bytesSplitKeep(b []byte, sep byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == sep {
			out = append(out, b[start:i+1])
			start = i + 1
		}
	}

	if start < len(b) {
		out = append(out, b[start:])
	}

	return out
}

func trimLastNewline(b []byte) []byte {
	if len(b) > 0 && b[len(b)-1] == '\n' {
		return b[:len(b)-1]
	}

	return b
}
