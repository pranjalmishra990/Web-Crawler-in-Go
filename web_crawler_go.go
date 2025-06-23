// ContentAnalyzer provides content analysis capabilities
type ContentAnalyzer struct {
	languageDetector *LanguageDetector
	keywordExtractor *KeywordExtractor
	sentimentAnalyzer *SentimentAnalyzer
}

// AnalysisResult contains content analysis results
type AnalysisResult struct {
	Language    string
	Keywords    []string
	Sentiment   float64  // -1 (negative) to 1 (positive)
	ReadingTime int      // Estimated reading time in minutes
	WordCount   int
	Links       LinkAnalysis
}

// LinkAnalysis provides link relationship analysis
type LinkAnalysis struct {
	InternalLinks int
	ExternalLinks int
	BrokenLinks   int
	NoFollowLinks int
	PageRank      float64 // Simplified PageRank score
}

// AnalyzeContent performs comprehensivepackage main

import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
	"golang.org/x/time/rate"
)

// CrawlResult represents the result of crawling a single URL
type CrawlResult struct {
	URL         string
	Title       string
	Links       []string
	Content     string
	StatusCode  int
	Error       error
	Depth       int
	ContentHash string
	Timestamp   time.Time
}

// CrawlerConfig holds configuration parameters for the crawler
type CrawlerConfig struct {
	MaxDepth           int
	MaxPages           int
	MaxConcurrency     int
	RequestDelay       time.Duration
	RequestTimeout     time.Duration
	UserAgent          string
	AllowedDomains     []string
	RespectRobots      bool
	FollowRedirects    bool
	MaxContentSize     int64         // Maximum content size to download
	AllowedContentTypes []string     // Allowed MIME types
	CustomHeaders      map[string]string // Custom HTTP headers
	ProxyURL           string        // HTTP proxy URL
	MaxRetries         int           // Maximum retry attempts
	RetryDelay         time.Duration // Delay between retries
	BloomFilterSize    int           // Size for Bloom filter (memory optimization)
	PolitenessDelay    time.Duration // Per-domain delay
}

// WebCrawler implements a concurrent, domain-respecting web crawler
type WebCrawler struct {
	config       CrawlerConfig
	visited      sync.Map
	results      chan CrawlResult
	workQueue    chan CrawlJob
	wg           sync.WaitGroup
	rateLimiter  *rate.Limiter
	client       *http.Client
	domainFilter map[string]bool
	urlRegex     *regexp.Regexp
	contentHash  sync.Map // Duplicate content detection
}

// CrawlJob represents a URL to be crawled with its depth
type CrawlJob struct {
	URL   string
	Depth int
}

// RobotsCache implements a comprehensive robots.txt parser and cache
type RobotsCache struct {
	cache     sync.Map
	mutex     sync.RWMutex
	client    *http.Client
	userAgent string
}

// RobotsRule represents a parsed robots.txt rule
type RobotsRule struct {
	UserAgent    string
	Disallow     []string
	Allow        []string
	CrawlDelay   time.Duration
	Sitemap      []string
	LastModified time.Time
}

// NewRobotsCache creates a new robots.txt cache
func NewRobotsCache(client *http.Client, userAgent string) *RobotsCache {
	return &RobotsCache{
		client:    client,
		userAgent: userAgent,
	}
}

// IsAllowed checks if crawling a URL is allowed by robots.txt
func (rc *RobotsCache) IsAllowed(targetURL string) (bool, time.Duration) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return false, 0
	}

	robotsURL := fmt.Sprintf("%s://%s/robots.txt", parsedURL.Scheme, parsedURL.Host)
	
	// Check cache first
	if cached, exists := rc.cache.Load(robotsURL); exists {
		rules := cached.(RobotsRule)
		return rc.checkRules(rules, parsedURL.Path), rules.CrawlDelay
	}

	// Fetch and parse robots.txt
	rules := rc.fetchRobots(robotsURL)
	rc.cache.Store(robotsURL, rules)
	
	return rc.checkRules(rules, parsedURL.Path), rules.CrawlDelay
}

// fetchRobots fetches and parses robots.txt
func (rc *RobotsCache) fetchRobots(robotsURL string) RobotsRule {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", robotsURL, nil)
	if err != nil {
		return RobotsRule{} // Default allow all
	}

	req.Header.Set("User-Agent", rc.userAgent)

	resp, err := rc.client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return RobotsRule{} // Default allow all if robots.txt not accessible
	}
	defer resp.Body.Close()

	return rc.parseRobots(resp.Body)
}

// parseRobots parses robots.txt content
func (rc *RobotsCache) parseRobots(reader io.Reader) RobotsRule {
	scanner := bufio.NewScanner(reader)
	var rules RobotsRule
	var currentUserAgent string
	var applicableToUs bool

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		field := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])

		switch field {
		case "user-agent":
			currentUserAgent = value
			applicableToUs = (value == "*" || strings.Contains(strings.ToLower(rc.userAgent), strings.ToLower(value)))
		case "disallow":
			if applicableToUs {
				rules.Disallow = append(rules.Disallow, value)
			}
		case "allow":
			if applicableToUs {
				rules.Allow = append(rules.Allow, value)
			}
		case "crawl-delay":
			if applicableToUs {
				if delay, err := time.ParseDuration(value + "s"); err == nil {
					rules.CrawlDelay = delay
				}
			}
		case "sitemap":
			rules.Sitemap = append(rules.Sitemap, value)
		}
	}

	rules.UserAgent = currentUserAgent
	rules.LastModified = time.Now()
	return rules
}

// checkRules evaluates if a path is allowed based on robots.txt rules
func (rc *RobotsCache) checkRules(rules RobotsRule, path string) bool {
	// Check Allow rules first (more specific)
	for _, allowRule := range rules.Allow {
		if rc.matchesRule(path, allowRule) {
			return true
		}
	}

	// Check Disallow rules
	for _, disallowRule := range rules.Disallow {
		if disallowRule == "" {
			continue // Empty disallow means allow all
		}
		if rc.matchesRule(path, disallowRule) {
			return false
		}
	}

	return true // Default allow
}

// matchesRule checks if a path matches a robots.txt rule pattern
func (rc *RobotsCache) matchesRule(path, rule string) bool {
	// Handle wildcard patterns
	if strings.Contains(rule, "*") {
		pattern := regexp.QuoteMeta(rule)
		pattern = strings.ReplaceAll(pattern, "\\*", ".*")
		pattern = "^" + pattern
		
		if matched, _ := regexp.MatchString(pattern, path); matched {
			return true
		}
	}

	// Exact prefix match
	return strings.HasPrefix(path, rule)
}

// NewWebCrawler creates a new web crawler instance
func NewWebCrawler(config CrawlerConfig) *WebCrawler {
	// Set default values
	if config.MaxDepth == 0 {
		config.MaxDepth = 3
	}
	if config.MaxPages == 0 {
		config.MaxPages = 100
	}
	if config.MaxConcurrency == 0 {
		config.MaxConcurrency = 10
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = 30 * time.Second
	}
	if config.UserAgent == "" {
		config.UserAgent = "Go-WebCrawler/1.0"
	}

	// Create domain filter map
	domainFilter := make(map[string]bool)
	for _, domain := range config.AllowedDomains {
		domainFilter[domain] = true
	}

	// URL validation regex
	urlRegex := regexp.MustCompile(`^https?://[^\s<>"{}|\\^` + "`" + `\[\]]+$`)

	// Rate limiter (requests per second)
	rateLimiter := rate.NewLimiter(rate.Every(config.RequestDelay), 1)

	// HTTP client with timeout
	client := &http.Client{
		Timeout: config.RequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !config.FollowRedirects {
				return http.ErrUseLastResponse
			}
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	return &WebCrawler{
		config:       config,
		results:      make(chan CrawlResult, config.MaxPages),
		workQueue:    make(chan CrawlJob, config.MaxPages*2),
		rateLimiter:  rateLimiter,
		client:       client,
		domainFilter: domainFilter,
		urlRegex:     urlRegex,
	}
}

// Crawl starts the crawling process from the given seed URLs
func (wc *WebCrawler) Crawl(ctx context.Context, seedURLs []string) <-chan CrawlResult {
	// Start worker goroutines
	for i := 0; i < wc.config.MaxConcurrency; i++ {
		wc.wg.Add(1)
		go wc.worker(ctx)
	}

	// Add seed URLs to work queue
	go func() {
		defer close(wc.workQueue)
		for _, seedURL := range seedURLs {
			select {
			case wc.workQueue <- CrawlJob{URL: seedURL, Depth: 0}:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wait for all workers to finish and close results channel
	go func() {
		wc.wg.Wait()
		close(wc.results)
	}()

	return wc.results
}

// worker processes URLs from the work queue
func (wc *WebCrawler) worker(ctx context.Context) {
	defer wc.wg.Done()

	for {
		select {
		case job, ok := <-wc.workQueue:
			if !ok {
				return
			}
			wc.processURL(ctx, job)
		case <-ctx.Done():
			return
		}
	}
}

// processURL crawls a single URL and extracts links
func (wc *WebCrawler) processURL(ctx context.Context, job CrawlJob) {
	// Check if already visited (atomic operation)
	if _, exists := wc.visited.LoadOrStore(job.URL, true); exists {
		return
	}

	// Check domain restrictions
	if !wc.isDomainAllowed(job.URL) {
		wc.results <- CrawlResult{
			URL:   job.URL,
			Error: fmt.Errorf("domain not allowed"),
			Depth: job.Depth,
		}
		return
	}

	// Rate limiting
	if err := wc.rateLimiter.Wait(ctx); err != nil {
		wc.results <- CrawlResult{
			URL:   job.URL,
			Error: err,
			Depth: job.Depth,
		}
		return
	}

	// Fetch the page
	result := wc.fetchPage(ctx, job.URL, job.Depth)

	// Check for duplicate content using hash
	if result.ContentHash != "" {
		if _, exists := wc.contentHash.LoadOrStore(result.ContentHash, job.URL); exists {
			result.Error = fmt.Errorf("duplicate content detected")
		}
	}

	// Send result
	select {
	case wc.results <- result:
	case <-ctx.Done():
		return
	}

	// Add discovered links to work queue if not at max depth
	if job.Depth < wc.config.MaxDepth && result.Error == nil {
		wc.addLinksToQueue(ctx, result.Links, job.Depth+1)
	}
}

// fetchPage performs the actual HTTP request and content extraction
func (wc *WebCrawler) fetchPage(ctx context.Context, pageURL string, depth int) CrawlResult {
	result := CrawlResult{
		URL:       pageURL,
		Depth:     depth,
		Timestamp: time.Now(),
	}

	// Create request with context
	req, err := http.NewRequestWithContext(ctx, "GET", pageURL, nil)
	if err != nil {
		result.Error = err
		return result
	}

	// Set user agent
	req.Header.Set("User-Agent", wc.config.UserAgent)

	// Perform request
	resp, err := wc.client.Do(req)
	if err != nil {
		result.Error = err
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode

	// Check for successful response
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		result.Error = fmt.Errorf("HTTP %d", resp.StatusCode)
		return result
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Error = err
		return result
	}

	// Parse HTML content
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		result.Error = err
		return result
	}

	// Extract title, links, and content
	result.Title = wc.extractTitle(doc)
	result.Links = wc.extractLinks(doc, pageURL)
	result.Content = wc.extractTextContent(doc)

	// Generate content hash for duplicate detection
	hasher := md5.New()
	hasher.Write([]byte(result.Content))
	result.ContentHash = hex.EncodeToString(hasher.Sum(nil))

	return result
}

// extractTitle extracts the page title from HTML
func (wc *WebCrawler) extractTitle(doc *html.Node) string {
	var title string
	var extractTitleText func(*html.Node)
	extractTitleText = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "title" {
			if n.FirstChild != nil && n.FirstChild.Type == html.TextNode {
				title = strings.TrimSpace(n.FirstChild.Data)
				return
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extractTitleText(c)
			if title != "" {
				return
			}
		}
	}
	extractTitleText(doc)
	return title
}

// extractLinks extracts all valid links from HTML
func (wc *WebCrawler) extractLinks(doc *html.Node, baseURL string) []string {
	var links []string
	var extractLinksRecursive func(*html.Node)
	
	extractLinksRecursive = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			for _, attr := range n.Attr {
				if attr.Key == "href" {
					link := wc.resolveURL(attr.Val, baseURL)
					if wc.isValidURL(link) {
						links = append(links, link)
					}
					break
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extractLinksRecursive(c)
		}
	}
	
	extractLinksRecursive(doc)
	return wc.deduplicateLinks(links)
}

// extractTextContent extracts readable text content from HTML
func (wc *WebCrawler) extractTextContent(doc *html.Node) string {
	var content strings.Builder
	var extractText func(*html.Node)
	
	extractText = func(n *html.Node) {
		// Skip script and style elements
		if n.Type == html.ElementNode && (n.Data == "script" || n.Data == "style") {
			return
		}
		
		if n.Type == html.TextNode {
			text := strings.TrimSpace(n.Data)
			if text != "" {
				content.WriteString(text)
				content.WriteString(" ")
			}
		}
		
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extractText(c)
		}
	}
	
	extractText(doc)
	return strings.TrimSpace(content.String())
}

// resolveURL resolves relative URLs to absolute URLs
func (wc *WebCrawler) resolveURL(href, baseURL string) string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	
	ref, err := url.Parse(href)
	if err != nil {
		return ""
	}
	
	resolved := base.ResolveReference(ref)
	return resolved.String()
}

// isValidURL checks if a URL is valid and should be crawled
func (wc *WebCrawler) isValidURL(u string) bool {
	if !wc.urlRegex.MatchString(u) {
		return false
	}
	
	parsed, err := url.Parse(u)
	if err != nil {
		return false
	}
	
	// Check for common non-crawlable file extensions
	path := strings.ToLower(parsed.Path)
	excludeExtensions := []string{".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", 
		".zip", ".rar", ".tar", ".gz", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg",
		".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv", ".css", ".js", ".xml", ".rss"}
	
	for _, ext := range excludeExtensions {
		if strings.HasSuffix(path, ext) {
			return false
		}
	}
	
	return true
}

// isDomainAllowed checks if the URL's domain is in the allowed list
func (wc *WebCrawler) isDomainAllowed(u string) bool {
	if len(wc.domainFilter) == 0 {
		return true // No domain restrictions
	}
	
	parsed, err := url.Parse(u)
	if err != nil {
		return false
	}
	
	domain := strings.ToLower(parsed.Host)
	
	// Check exact match
	if wc.domainFilter[domain] {
		return true
	}
	
	// Check subdomain match
	for allowedDomain := range wc.domainFilter {
		if strings.HasSuffix(domain, "."+allowedDomain) {
			return true
		}
	}
	
	return false
}

// addLinksToQueue adds discovered links to the work queue
func (wc *WebCrawler) addLinksToQueue(ctx context.Context, links []string, depth int) {
	for _, link := range links {
		select {
		case wc.workQueue <- CrawlJob{URL: link, Depth: depth}:
		case <-ctx.Done():
			return
		default:
			// Queue is full, skip this link
		}
	}
}

// deduplicateLinks removes duplicate URLs from a slice
func (wc *WebCrawler) deduplicateLinks(links []string) []string {
	seen := make(map[string]bool)
	var unique []string
	
	for _, link := range links {
		if !seen[link] {
			seen[link] = true
			unique = append(unique, link)
		}
	}
	
	return unique
}

// Example usage and demonstration
func main() {
	// Configure the crawler
	config := CrawlerConfig{
		MaxDepth:        2,
		MaxPages:        50,
		MaxConcurrency:  5,
		RequestDelay:    100 * time.Millisecond,
		RequestTimeout:  30 * time.Second,
		UserAgent:       "Go-WebCrawler-Demo/1.0",
		AllowedDomains:  []string{"example.com", "httpbin.org"},
		RespectRobots:   true,
		FollowRedirects: true,
	}

	// Create crawler instance
	crawler := NewWebCrawler(config)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minutes)
	defer cancel()

	// Seed URLs
	seedURLs := []string{
		"https://httpbin.org/",
		"https://example.com/",
	}

	fmt.Println("Starting web crawl...")
	fmt.Printf("Configuration: MaxDepth=%d, MaxPages=%d, MaxConcurrency=%d\n", 
		config.MaxDepth, config.MaxPages, config.MaxConcurrency)
	fmt.Println("Seed URLs:", seedURLs)
	fmt.Println(strings.Repeat("-", 80))

	// Start crawling
	results := crawler.Crawl(ctx, seedURLs)

	// Process results
	crawledCount := 0
	errorCount := 0
	
	for result := range results {
		crawledCount++
		if result.Error != nil {
			errorCount++
			fmt.Printf("ERROR [Depth %d] %s: %v\n", result.Depth, result.URL, result.Error)
		} else {
			fmt.Printf("SUCCESS [Depth %d] %s\n", result.Depth, result.URL)
			fmt.Printf("  Title: %s\n", result.Title)
			fmt.Printf("  Status: %d\n", result.StatusCode)
			fmt.Printf("  Links found: %d\n", len(result.Links))
			fmt.Printf("  Content length: %d characters\n", len(result.Content))
			fmt.Printf("  Content hash: %s\n", result.ContentHash)
			
			// Show first few links
			if len(result.Links) > 0 {
				fmt.Println("  Sample links:")
				for i, link := range result.Links {
					if i >= 3 {
						fmt.Printf("    ... and %d more\n", len(result.Links)-3)
						break
					}
					fmt.Printf("    %s\n", link)
				}
			}
		}
		fmt.Println(strings.Repeat("-", 80))
	}

	fmt.Printf("\nCrawl completed!\n")
	fmt.Printf("Total pages processed: %d\n", crawledCount)
	fmt.Printf("Successful crawls: %d\n", crawledCount-errorCount)
	fmt.Printf("Errors encountered: %d\n", errorCount)
}