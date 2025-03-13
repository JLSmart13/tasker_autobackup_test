// ==UserScript==
// @name         Enhanced Image Collector
// @namespace    http://tampermonkey.net/
// @version      0.3
// @description  Advanced image collector with site-agnostic full-size image detection and junk filtering
// @author       JLSmart13
// @match        *://*/*
// @grant        GM_xmlhttpRequest
// @grant        GM_download
// @run-at       document-idle
// ==/UserScript==

(function() {
    'use strict';
    
    // Create floating button
    const floatingButton = document.createElement('div');
    floatingButton.textContent = '📷';
    floatingButton.style.cssText = `
        position: fixed;
        top: 10px;
        left: 10px;
        width: 40px;
        height: 40px;
        background: #3498db;
        color: white;
        border-radius: 50%;
        text-align: center;
        line-height: 40px;
        font-size: 20px;
        cursor: pointer;
        z-index: 9999;
        box-shadow: 0 2px 5px rgba(0,0,0,0.3);
    `;
    document.body.appendChild(floatingButton);

    // Create gallery container that will be shown when button is clicked
    const galleryContainer = document.createElement('div');
    galleryContainer.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0,0,0,0.9);
        display: none;
        flex-direction: column;
        z-index: 10000;
        overflow-y: auto;
    `;
    document.body.appendChild(galleryContainer);

    // Gallery header with controls
    const galleryHeader = document.createElement('div');
    galleryHeader.style.cssText = `
        position: sticky;
        top: 0;
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 10px;
        background: #333;
        color: white;
        z-index: 10001;
    `;
    galleryContainer.appendChild(galleryHeader);

    // Close button
    const closeButton = document.createElement('button');
    closeButton.textContent = '✖';
    closeButton.style.cssText = `
        background: #e74c3c;
        color: white;
        border: none;
        border-radius: 50%;
        width: 30px;
        height: 30px;
        cursor: pointer;
        font-size: 16px;
    `;
    galleryHeader.appendChild(closeButton);

    // Status counter
    const statusCounter = document.createElement('div');
    statusCounter.textContent = 'Loading...';
    statusCounter.style.cssText = `
        font-size: 16px;
    `;
    galleryHeader.appendChild(statusCounter);

    // Download all button
    const downloadAllButton = document.createElement('button');
    downloadAllButton.textContent = 'Download All';
    downloadAllButton.style.cssText = `
        background: #2ecc71;
        color: white;
        border: none;
        border-radius: 4px;
        padding: 5px 10px;
        cursor: pointer;
        font-size: 14px;
    `;
    galleryHeader.appendChild(downloadAllButton);

    // Filter controls
    const filterControls = document.createElement('div');
    filterControls.style.cssText = `
        display: flex;
        gap: 10px;
        align-items: center;
        margin-right: 20px;
    `;
    
    const minWidthInput = document.createElement('input');
    minWidthInput.type = 'number';
    minWidthInput.placeholder = 'Min width';
    minWidthInput.style.cssText = `
        width: 80px;
        padding: 3px;
        border-radius: 3px;
        border: none;
    `;
    
    const filterButton = document.createElement('button');
    filterButton.textContent = 'Filter';
    filterButton.style.cssText = `
        background: #f39c12;
        color: white;
        border: none;
        border-radius: 4px;
        padding: 3px 8px;
        cursor: pointer;
        font-size: 12px;
    `;
    
    filterControls.appendChild(minWidthInput);
    filterControls.appendChild(filterButton);
    galleryHeader.insertBefore(filterControls, downloadAllButton);

    // Image grid container
    const imageGrid = document.createElement('div');
    imageGrid.style.cssText = `
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
        grid-gap: 10px;
        padding: 10px;
    `;
    galleryContainer.appendChild(imageGrid);

    // Sets to keep track of processed URLs and images to avoid duplicates
    let processedPageUrls = new Set();
    let processedImageUrls = new Set();
    let foundImages = [];
    let imageGroups = new Map(); // baseName -> {url, size, width, height}
    let pendingLinks = [];
    let isProcessing = false;
    
    // Function to check if URL is an image
    function isImageUrl(url) {
        return /\.(jpeg|jpg|gif|png|webp|bmp|avif|svg)(\?.*)?$/i.test(url);
    }
    
    // Function to get absolute URL from relative URL
    function getAbsoluteUrl(baseUrl, relativeUrl) {
        try {
            return new URL(relativeUrl, baseUrl).href;
        } catch (e) {
            return null;
        }
    }
    
    // Function to fetch content from a URL
    function fetchUrl(url) {
        return new Promise((resolve, reject) => {
            GM_xmlhttpRequest({
                method: 'GET',
                url: url,
                onload: function(response) {
                    resolve(response);
                },
                onerror: function(error) {
                    reject(error);
                },
                timeout: 10000
            });
        });
    }

    // Function to detect junk images (ads, UI elements, logos, icons)
    function isJunkImage(imageUrl, width, height) {
        // 1. Size-based detection: very small images are often icons, buttons, or decorations
        const isTooSmall = (width && height) && (width < 100 || height < 100);
        
        // 2. URL pattern detection for common advertising and tracking images
        const adPatterns = [
            /\/ads?\//i,              // /ad/ or /ads/ in path
            /\/banners?\//i,          // /banner/ or /banners/ in path
            /\/sponsors?\//i,         // /sponsor/ or /sponsors/ in path
            /adserver/i,              // adserver in domain
            /analytics/i,             // analytics in URL
            /tracking/i,              // tracking in URL
            /pixel\.(gif|png)/i,      // tracking pixels
            /transparent\.(gif|png)/i,// transparent placeholders
            /banner/i,                // banner in filename
            /advertisement/i,         // advertisement in URL
            /doubleclick/i,           // Google ads
            /pagead/i,                // Google page ads
            /googleads/i,             // Google ads
            /adsystem/i,              // Ad systems
            /adimg/i,                 // Ad images
            /advert/i,                // Advertising
            /affiliate/i              // Affiliate marketing
        ];
        
        // 3. Common UI element patterns
        const uiPatterns = [
            /\/icons?\//i,            // /icon/ or /icons/ in path
            /\/buttons?\//i,          // /button/ or /buttons/ in path
            /\/logos?\//i,            // /logo/ or /logos/ in path
            /\/header/i,              // Header images
            /\/footer/i,              // Footer images
            /\/bg\./i,                // Background images
            /background/i,            // Background images
            /icon[_-]/i,              // icon_ or icon- in filename
            /logo[_-]/i,              // logo_ or logo- in filename
            /button[_-]/i,            // button_ or button- in filename
            /separator/i,             // Separators
            /divider/i,               // Dividers
            /bullet/i,                // Bullet points
            /sprite/i,                // CSS sprites
            /loading/i,               // Loading indicators
            /spinner/i,               // Spinners
            /arrow/i,                 // Navigation arrows
            /badge/i                  // Badges and icons
        ];
        
        // 4. Common site asset locations
        const assetPatterns = [
            /\/assets\//i,            // Common asset directory
            /\/static\//i,            // Static assets
            /\/images\/ui\//i,        // UI images
            /\/themes?\//i,           // Theme assets
            /\/wp-content\/themes\//i,// WordPress themes
            /\/templates?\//i,        // Template assets
            /\/css\//i,               // CSS directory often has UI images
            /\/styles?\//i            // Styles directory
        ];
        
        // Check if the URL matches any of the patterns
        const isAdUrl = adPatterns.some(pattern => pattern.test(imageUrl));
        const isUiUrl = uiPatterns.some(pattern => pattern.test(imageUrl));
        
        // For asset directories, only filter if it also seems small or has UI/icon in the name
        const isAssetUrl = assetPatterns.some(pattern => pattern.test(imageUrl)) && 
                          (isTooSmall || /icon|ui|button|logo/i.test(imageUrl));
        
        // 5. Detect by aspect ratio - extremely wide or tall images are often banners or decorations
        let extremeAspectRatio = false;
        if (width && height) {
            const ratio = width / height;
            extremeAspectRatio = ratio > 5 || ratio < 0.2; // Very wide or very tall
        }
        
        // 6. Filename patterns for common junk images
        const junkFilenames = [
            /spacer\.(gif|png)/i,     // Spacer images
            /blank\.(gif|png)/i,      // Blank images
            /empty\.(gif|png)/i,      // Empty images
            /dot\.(gif|png)/i,        // Dot images
            /pixel\.(gif|png)/i,      // Pixel images
            /transparent\.(gif|png)/i // Transparent images
        ];
        
        const isJunkFilename = junkFilenames.some(pattern => pattern.test(imageUrl));
        
        // Combine all checks
        return isTooSmall || isAdUrl || isUiUrl || isAssetUrl || extremeAspectRatio || isJunkFilename;
    }
    
    // Enhanced function to find the full-size image URL with site-agnostic detection
    async function getFullSizeImageUrl(imageUrl, baseUrl, depth = 0) {
        // Prevent excessive recursion
        if (depth > 3) {
            return imageUrl;
        }
        
        // Common patterns for thumbnail identifiers in URLs
        const thumbnailPatterns = [
            /\/t_([^\/]+)$/i,        // /t_[hash]
            /\/thumbs?\/([^\/]+)$/i,  // /thumb/[filename] or /thumbs/[filename]
            /\/thumbnails?\/([^\/]+)$/i, // /thumbnail/[filename]
            /[-_]thumb[-_]/i,        // filename-thumb-etc or filename_thumb_etc
            /[-_]small[-_]/i,        // filename-small-etc
            /[-_]preview[-_]/i,      // filename-preview-etc
            /[-_](?:\d+x\d+)[-_]/i,  // filename-123x456-etc (dimensions in filename)
            /\/(?:\d+x\d+)\/([^\/]+)$/i // /123x456/filename (dimensions in path)
        ];
        
        // Check if URL already appears to be a full-size image
        if (isImageUrl(imageUrl)) {
            // Try to detect if this is a thumbnail despite having an image extension
            let isThumbnail = false;
            for (const pattern of thumbnailPatterns) {
                if (pattern.test(imageUrl)) {
                    isThumbnail = true;
                    break;
                }
            }
            
            if (!isThumbnail || depth > 0) {
                return imageUrl; // Already a full image or we've already tried to find a larger one
            }
        }
        
        // Try to generate possible full-size URLs based on thumbnail URL patterns
        const potentialFullSizeUrls = [];
        
        // 1. Try removing thumbnail identifiers
        for (const pattern of thumbnailPatterns) {
            if (pattern.test(imageUrl)) {
                // Try different transformations based on the pattern
                if (/\/t_([^\/]+)$/i.test(imageUrl)) {
                    // t_ prefix pattern (like in your example)
                    const fullSizeUrl = imageUrl.replace(/\/t_([^\/]+)$/i, '/$1');
                    
                    // Try with common image extensions if the URL doesn't have one
                    if (!isImageUrl(fullSizeUrl)) {
                        ['.jpg', '.jpeg', '.png', '.webp'].forEach(ext => {
                            potentialFullSizeUrls.push(fullSizeUrl + ext);
                        });
                    } else {
                        potentialFullSizeUrls.push(fullSizeUrl);
                    }
                } else if (/\/thumbs?\/([^\/]+)$/i.test(imageUrl)) {
                    // /thumb/ or /thumbs/ pattern
                    const filename = imageUrl.match(/\/thumbs?\/([^\/]+)$/i)[1];
                    potentialFullSizeUrls.push(imageUrl.replace(/\/thumbs?\/([^\/]+)$/i, '/images/$1'));
                    potentialFullSizeUrls.push(imageUrl.replace(/\/thumbs?\/([^\/]+)$/i, '/full/$1'));
                    potentialFullSizeUrls.push(imageUrl.replace(/\/thumbs?\/([^\/]+)$/i, '/$1'));
                } else if (/[-_]thumb[-_]/i.test(imageUrl)) {
                    // -thumb- or _thumb_ pattern
                    potentialFullSizeUrls.push(imageUrl.replace(/[-_]thumb[-_]/i, '-'));
                    potentialFullSizeUrls.push(imageUrl.replace(/[-_]thumb[-_]/i, '_'));
                } else if (/[-_](?:\d+x\d+)[-_]/i.test(imageUrl)) {
                    // Remove dimensions like -300x200-
                    potentialFullSizeUrls.push(imageUrl.replace(/[-_](?:\d+x\d+)[-_]/i, '-'));
                    potentialFullSizeUrls.push(imageUrl.replace(/[-_](?:\d+x\d+)[-_]/i, '_'));
                }
            }
        }
        
        // 2. Try common size modifiers
        // For URLs with /s/ or /m/ as size indicators (common in CDNs and image hosts)
        if (/\/[sm]\//.test(imageUrl)) {
            potentialFullSizeUrls.push(imageUrl.replace(/\/[sm]\//, '/l/'));
            potentialFullSizeUrls.push(imageUrl.replace(/\/[sm]\//, '/xl/'));
            potentialFullSizeUrls.push(imageUrl.replace(/\/[sm]\//, '/original/'));
        }
        
        // 3. Try to follow the link and look for pointers to full images
        try {
            const response = await fetchUrl(imageUrl);
            
            // If the URL redirects to an image, use that
            const contentType = response.responseHeaders.match(/content-type:\s*image\/[^\s;]*/i);
            if (contentType) {
                return imageUrl; // It's already an image
            }
            
            // Parse HTML to find links to full images
            const parser = new DOMParser();
            const doc = parser.parseFromString(response.responseText, 'text/html');
            
            // Look for common patterns in HTML that point to full images
            
            // A. Find links that directly point to images
            const imageLinks = Array.from(doc.querySelectorAll('a[href$=".jpg"], a[href$=".jpeg"], a[href$=".png"], a[href$=".webp"]'));
            for (const link of imageLinks) {
                const href = link.getAttribute('href');
                if (href) {
                    const fullUrl = getAbsoluteUrl(imageUrl, href);
                    if (fullUrl) potentialFullSizeUrls.push(fullUrl);
                }
            }
            
            // B. Find links with text suggesting they lead to full images
            const fullSizeTextLinks = Array.from(doc.querySelectorAll('a'));
            for (const link of fullSizeTextLinks) {
                const text = link.textContent.toLowerCase();
                const href = link.getAttribute('href');
                if (href && (text.includes('full') || text.includes('original') || 
                            text.includes('large') || text.includes('high') || 
                            text.includes('view image') || text.includes('zoom'))) {
                    const fullUrl = getAbsoluteUrl(imageUrl, href);
                    if (fullUrl) potentialFullSizeUrls.push(fullUrl);
                }
            }
            
            // C. Find image tags with data attributes suggesting full size versions
            const images = Array.from(doc.querySelectorAll('img'));
            for (const img of images) {
                // Look for data attributes that might contain full-size URLs
                for (const attr of img.attributes) {
                    if (/^data-(?:full|original|large|source|high|zoom)/i.test(attr.name)) {
                        const fullUrl = getAbsoluteUrl(imageUrl, attr.value);
                        if (fullUrl) potentialFullSizeUrls.push(fullUrl);
                    }
                }
            }
            
            // D. Check for OpenGraph images (often full size)
            const metaTags = Array.from(doc.querySelectorAll('meta[property^="og:image"]'));
            for (const meta of metaTags) {
                const content = meta.getAttribute('content');
                if (content) {
                    const fullUrl = getAbsoluteUrl(imageUrl, content);
                    if (fullUrl) potentialFullSizeUrls.push(fullUrl);
                }
            }
        } catch (error) {
            console.error(`Error fetching ${imageUrl}: ${error.message}`);
        }
        
        // Try each potential full-size URL
        for (const url of potentialFullSizeUrls) {
            try {
                // Check if this is an actual full-size image
                const response = await fetchUrl(url);
                const contentType = response.responseHeaders.match(/content-type:\s*image\/[^\s;]*/i);
                
                if (contentType) {
                    // Check if the image is actually larger
                    // We might need to rely on header info or URL pattern assessment
                    const filesizeHeader = response.responseHeaders.match(/content-length:\s*(\d+)/i);
                    if (filesizeHeader) {
                        const size = parseInt(filesizeHeader[1]);
                        // If the image is significantly larger, it's likely the full version
                        if (size > 50000) { // Arbitrary threshold, adjust as needed
                            return url;
                        }
                    } else {
                        // If we can't determine size, assume it's the full version
                        return url;
                    }
                } else if (!isImageUrl(url)) {
                    // If not an image, it might be another HTML page we should check
                    const deeperImage = await getFullSizeImageUrl(url, imageUrl, depth + 1);
                    if (deeperImage !== url) {
                        return deeperImage;
                    }
                }
            } catch (error) {
                console.error(`Error checking potential full-size URL ${url}: ${error.message}`);
            }
        }
        
        // If we couldn't find a better version, return the original
        return imageUrl;
    }

    // Enhanced function to identify similar images across different naming patterns
    function getImageBaseName(url) {
        // Extract the filename from the URL
        let filename = url.split('/').pop().split('?')[0];
        
        // Remove common file extensions
        filename = filename.replace(/\.(jpg|jpeg|png|gif|webp|bmp)$/i, '');
        
        // Remove thumbnail identifiers
        filename = filename
            // Remove dimensions in filenames (e.g., image-800x600 → image)
            .replace(/-\d+x\d+(?=($|\.))/, '')
            .replace(/_\d+x\d+(?=($|\.))/, '')
            // Remove common size indicators
            .replace(/[-_](small|medium|large|thumb|tiny|preview)(?=($|\.))/, '')
            .replace(/[-_](sm|md|lg|xl|xxl|orig)(?=($|\.))/, '')
            // Remove numbered variants
            .replace(/[-_]\d+(?=($|\.))/, '')
            // Remove hash-like identifiers (often added by CDNs)
            .replace(/[-_][a-f0-9]{8,}(?=($|\.))/, '');
        
        // Extract core part of hashed filenames (like in your example)
        // If the filename is just a hash (common in media servers)
        if (/^[a-f0-9]{20,}$/i.test(filename)) {
            // Create a fingerprint from part of the hash
            return filename.substring(0, 16);
        }
        
        return filename;
    }

    // Function to estimate if an image URL is likely to be a thumbnail
    function isThumbnailUrl(url) {
        const thumbnailIndicators = [
            /\/t_/i,               // /t_ prefix (like in your example)
            /\/thumbs?\//i,        // /thumb/ or /thumbs/ in path
            /\/thumbnails?\//i,    // /thumbnail/ in path
            /\/s\//i,              // /s/ size indicator (small)
            /\/m\//i,              // /m/ size indicator (medium)
            /-thumb/i,             // -thumb in filename
            /_thumb/i,             // _thumb in filename
            /-small/i,             // -small in filename
            /-preview/i,           // -preview in filename
            /-\d{2,3}x\d{2,3}/i,   // small dimensions like -300x200
            /\bw=\d{2,3}/i         // width parameter with small value
        ];
        
        for (const pattern of thumbnailIndicators) {
            if (pattern.test(url)) {
                return true;
            }
        }
        
        return false;
    }

    // Function to compare two URLs and determine which is likely the larger image
    function compareProbableImageSizes(urlA, urlB) {
        // Check for common thumbnail patterns in each URL
        const aIsThumbnail = isThumbnailUrl(urlA);
        const bIsThumbnail = isThumbnailUrl(urlB);
        
        // If one is a thumbnail and the other isn't
        if (aIsThumbnail && !bIsThumbnail) return -1; // A is smaller
        if (!aIsThumbnail && bIsThumbnail) return 1;  // A is larger
        
        // Look for dimensions in the URLs
        const aDims = urlA.match(/[-_\/](\d{2,4})x(\d{2,4})[-_\/\.]/i);
        const bDims = urlB.match(/[-_\/](\d{2,4})x(\d{2,4})[-_\/\.]/i);
        
        if (aDims && bDims) {
            const aSize = parseInt(aDims[1]) * parseInt(aDims[2]);
            const bSize = parseInt(bDims[1]) * parseInt(bDims[2]);
            return aSize - bSize; // Positive if A is larger
        }
        
        // Look for size indicators in filenames
        const sizePriority = {
            'full': 100,
            'original': 90,
            'high': 80,
            'large': 70,
            'xl': 60,
            'lg': 50,
            'medium': 40,
            'md': 30,
            'small': 20,
            'sm': 10,
            'thumb': 0,
            'tiny': -10
        };
        
        for (const [term, priority] of Object.entries(sizePriority)) {
            const aHas = new RegExp(`[-_]${term}[-_\\.]`, 'i').test(urlA);
            const bHas = new RegExp(`[-_]${term}[-_\\.]`, 'i').test(urlB);
            
            if (aHas && !bHas) return priority; // Positive for higher priority
            if (!aHas && bHas) return -priority; // Negative for lower priority
        }
        
        // If no clear indicators, prefer URLs with fewer transformative parts
        const aTransforms = (urlA.match(/[_-](resize|scale|crop|thumb)/gi) || []).length;
        const bTransforms = (urlB.match(/[_-](resize|scale|crop|thumb)/gi) || []).length;
        
        if (aTransforms !== bTransforms) {
            return bTransforms - aTransforms; // Fewer transformations likely means original
        }
        
        // Check URL length - sometimes longer URLs have more transformations
        // This is a weak heuristic but can help as a last resort
        return urlB.length - urlA.length;
    }

    // Function to add a temporary placeholder while the image is being processed
    function addTempImagePlaceholder(imageUrl, tempId) {
        const imageContainer = document.createElement('div');
        imageContainer.id = tempId;
        imageContainer.setAttribute('data-temp-url', imageUrl);
        imageContainer.style.cssText = `
            background: #333;
            border-radius: 5px;
            overflow: hidden;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            height: 200px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.2);
        `;
        
        const loadingIndicator = document.createElement('div');
        loadingIndicator.style.cssText = `
            width: 40px;
            height: 40px;
            border: 4px solid #444;
            border-top: 4px solid #3498db;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        `;
        
        const styleAnimation = document.createElement('style');
        styleAnimation.textContent = `
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
        `;
        document.head.appendChild(styleAnimation);
        
        const loadingText = document.createElement('div');
        loadingText.textContent = 'Finding best version...';
        loadingText.style.cssText = `
            color: #ccc;
            margin-top: 10px;
            font-size: 12px;
        `;
        
        imageContainer.appendChild(loadingIndicator);
        imageContainer.appendChild(loadingText);
        imageGrid.appendChild(imageContainer);
    }

    // Function to replace a placeholder with an actual image
    function createImageInContainer(imageUrl, container) {
        // Clear the container
        container.innerHTML = '';
        container.style.cssText = `
            background: #444;
            border-radius: 5px;
            overflow: hidden;
            display: flex;
            flex-direction: column;
            box-shadow: 0 2px 5px rgba(0,0,0,0.2);
        `;
        container.removeAttribute('data-temp-url');
        container.setAttribute('data-image-url', imageUrl);
        
        // Create image element
        const img = document.createElement('img');
        img.style.cssText = `
            width: 100%;
            height: 200px;
            object-fit: contain;
            background: #222;
        `;
        img.src = imageUrl;
        img.loading = 'lazy';
        
        // Show full image on click
        img.addEventListener('click', () => {
            showFullSizeViewer(imageUrl);
        });
        
        // Image info display
        const imageUrl_display = document.createElement('div');
        imageUrl_display.style.cssText = `
            padding: 5px;
            font-size: 12px;
            color: #ddd;
            text-overflow: ellipsis;
            overflow: hidden;
            white-space: nowrap;
        `;
        imageUrl_display.textContent = imageUrl.split('/').pop();
        
        // Download button
        const downloadButton = document.createElement('button');
        downloadButton.textContent = '⬇️';
        downloadButton.style.cssText = `
            background: #3498db;
            color: white;
            border: none;
            padding: 5px;
            cursor: pointer;
            margin-top: auto;
        `;
        
        downloadButton.addEventListener('click', (e) => {
            e.stopPropagation();
            const filename = imageUrl.split('/').pop().split('?')[0] || 'image.jpg';
            GM_download({
                url: imageUrl,
                name: filename
            });
        });
        
        container.appendChild(img);
        container.appendChild(imageUrl_display);
        container.appendChild(downloadButton);
    }

    // Function to update or add an image to the gallery
    function updateOrAddImageInGallery(originalUrl, fullSizeUrl, tempId) {
        // Check if this is a new image or we need to update one
        const tempElement = document.getElementById(tempId);
        
        // Get base name to identify similar images
        const baseName = getImageBaseName(fullSizeUrl);
        
        // Check if we already have this image in another form
        if (imageGroups.has(baseName) && imageGroups.get(baseName).url !== fullSizeUrl) {
            const existing = imageGroups.get(baseName);
            
            // Compare which URL is likely to be larger
            const comparison = compareProbableImageSizes(fullSizeUrl, existing.url);
            
            // If new URL seems to be a larger version
            if (comparison > 0) {
                // Update with the better version
                const index = foundImages.indexOf(existing.url);
                if (index !== -1) {
                    foundImages[index] = fullSizeUrl;
                    updateImageInGallery(existing.url, fullSizeUrl);
                    imageGroups.set(baseName, {url: fullSizeUrl});
                }
            }
            
            // Remove the temporary placeholder since we already have this image
            if (tempElement) {
                imageGrid.removeChild(tempElement);
            }
            
            return;
        }
        
        // This is a new unique image
        if (tempElement) {
            // Replace the placeholder with the actual image
            createImageInContainer(fullSizeUrl, tempElement);
        } else {
            // Create a new image element
            createImageInGallery(fullSizeUrl);
        }
        
        // Add to tracking collections
                foundImages.push(fullSizeUrl);
        imageGroups.set(baseName, {url: fullSizeUrl});
        
        // Update counter
        updateCounter();
    }

    // Function to create a new image in the gallery
    function createImageInGallery(imageUrl) {
        const imageContainer = document.createElement('div');
        imageContainer.setAttribute('data-image-url', imageUrl);
        imageContainer.style.cssText = `
            background: #444;
            border-radius: 5px;
            overflow: hidden;
            display: flex;
            flex-direction: column;
            box-shadow: 0 2px 5px rgba(0,0,0,0.2);
        `;
        
        const img = document.createElement('img');
        img.style.cssText = `
            width: 100%;
            height: 200px;
            object-fit: contain;
            background: #222;
        `;
        img.src = imageUrl;
        img.loading = 'lazy';
        
        // Show full image on click
        img.addEventListener('click', () => {
            showFullSizeViewer(imageUrl);
        });
        
        const imageUrl_display = document.createElement('div');
        imageUrl_display.style.cssText = `
            padding: 5px;
            font-size: 12px;
            color: #ddd;
            text-overflow: ellipsis;
            overflow: hidden;
            white-space: nowrap;
        `;
        imageUrl_display.textContent = imageUrl.split('/').pop();
        
        const downloadButton = document.createElement('button');
        downloadButton.textContent = '⬇️';
        downloadButton.style.cssText = `
            background: #3498db;
            color: white;
            border: none;
            padding: 5px;
            cursor: pointer;
            margin-top: auto;
        `;
        
        downloadButton.addEventListener('click', (e) => {
            e.stopPropagation();
            const filename = imageUrl.split('/').pop().split('?')[0] || 'image.jpg';
            GM_download({
                url: imageUrl,
                name: filename
            });
        });
        
        imageContainer.appendChild(img);
        imageContainer.appendChild(imageUrl_display);
        imageContainer.appendChild(downloadButton);
        imageGrid.appendChild(imageContainer);
    }

    // Function to update an image in the gallery
    function updateImageInGallery(oldUrl, newUrl) {
        // Find the container with the old image
        const containers = Array.from(imageGrid.children);
        for (const container of containers) {
            if (container.getAttribute('data-image-url') === oldUrl) {
                // Update the container's data attribute
                container.setAttribute('data-image-url', newUrl);
                
                // Update the image src
                const img = container.querySelector('img');
                if (img) img.src = newUrl;
                
                // Update the text display
                const display = container.querySelector('div');
                if (display) display.textContent = newUrl.split('/').pop();
                
                // Update the download button
                const downloadButton = container.querySelector('button');
                if (downloadButton) {
                    downloadButton.onclick = (e) => {
                        e.stopPropagation();
                        const filename = newUrl.split('/').pop().split('?')[0] || 'image.jpg';
                        GM_download({
                            url: newUrl,
                            name: filename
                        });
                    };
                }
                
                break;
            }
        }
    }

    // Function to show a fullscreen view of the image
    function showFullSizeViewer(imageUrl) {
        const fullView = document.createElement('div');
        fullView.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.95);
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            z-index: 10002;
        `;
        
        const fullImg = document.createElement('img');
        fullImg.style.cssText = `
            max-width: 95%;
            max-height: 90%;
            object-fit: contain;
        `;
        fullImg.src = imageUrl;
        
        const closeFullView = document.createElement('button');
        closeFullView.textContent = '✖';
        closeFullView.style.cssText = `
            position: absolute;
            top: 10px;
            right: 10px;
            background: #e74c3c;
            color: white;
            border: none;
            border-radius: 50%;
            width: 30px;
            height: 30px;
            cursor: pointer;
            font-size: 16px;
        `;
        
        closeFullView.addEventListener('click', () => {
            document.body.removeChild(fullView);
        });
        
        // Also close on click outside the image
        fullView.addEventListener('click', (e) => {
            if (e.target === fullView) {
                document.body.removeChild(fullView);
            }
        });
        
        // Add download button in full view
        const downloadButton = document.createElement('button');
        downloadButton.textContent = 'Download';
        downloadButton.style.cssText = `
            position: absolute;
            bottom: 20px;
            background: #3498db;
            color: white;
            border: none;
            border-radius: 4px;
            padding: 8px 15px;
            cursor: pointer;
            font-size: 14px;
        `;
        
        downloadButton.addEventListener('click', () => {
            const filename = imageUrl.split('/').pop().split('?')[0] || 'image.jpg';
            GM_download({
                url: imageUrl,
                name: filename
            });
        });
        
        fullView.appendChild(fullImg);
        fullView.appendChild(closeFullView);
        fullView.appendChild(downloadButton);
        document.body.appendChild(fullView);
    }

    // Function to extract image URLs from HTML
    async function extractImagesFromHtml(htmlContent, baseUrl) {
        const parser = new DOMParser();
        const doc = parser.parseFromString(htmlContent, 'text/html');
        
        // Find all standard images
        const images = Array.from(doc.querySelectorAll('img'));
        const imageUrls = [];
        
        // Process images in batches to avoid overwhelming the browser
        const processBatch = async (startIndex, batchSize) => {
            const endIndex = Math.min(startIndex + batchSize, images.length);
            const batch = images.slice(startIndex, endIndex);
            
            for (const img of batch) {
                let src = img.getAttribute('src') || 
                          img.getAttribute('data-src') || 
                          img.getAttribute('data-original');
                
                if (src) {
                    const fullUrl = getAbsoluteUrl(baseUrl, src);
                    
                    if (fullUrl && !processedImageUrls.has(fullUrl)) {
                        // Get image dimensions from attributes or CSS
                        const width = parseInt(img.getAttribute('width') || img.style.width || '0');
                        const height = parseInt(img.getAttribute('height') || img.style.height || '0');
                        
                        // Skip junk images
                        if (isJunkImage(fullUrl, width, height)) {
                            continue;
                        }
                        
                        processedImageUrls.add(fullUrl);
                        
                        // Get the full size image URL and add to gallery immediately
                        try {
                            // Add a temporary placeholder while we find the full-size version
                            const tempId = 'temp-' + Math.random().toString(36).substring(2, 15);
                            addTempImagePlaceholder(fullUrl, tempId);
                            
                            // Find full-size version asynchronously
                            const fullSizeUrl = await getFullSizeImageUrl(fullUrl, baseUrl);
                            
                            // Replace placeholder with actual image or add new if needed
                            updateOrAddImageInGallery(fullUrl, fullSizeUrl, tempId);
                            
                            imageUrls.push(fullSizeUrl);
                        } catch (error) {
                            console.error(`Error processing image ${fullUrl}:`, error);
                        }
                    }
                }
            }
            
            // Process next batch if there are more images
            if (endIndex < images.length) {
                setTimeout(() => processBatch(endIndex, batchSize), 10);
            }
        };
        
        // Start processing in batches of 5
        processBatch(0, 5);
        
        // Also find links to images in parallel
        const links = Array.from(doc.querySelectorAll('a'));
        
        for (const link of links) {
            let href = link.getAttribute('href');
            
            if (href) {
                const fullUrl = getAbsoluteUrl(baseUrl, href);
                
                if (fullUrl && isImageUrl(fullUrl) && !processedImageUrls.has(fullUrl)) {
                    // Skip junk images by URL pattern
                    if (isJunkImage(fullUrl, 0, 0)) {
                        continue;
                    }
                    
                    processedImageUrls.add(fullUrl);
                    
                    try {
                        // Add a temporary placeholder
                        const tempId = 'temp-' + Math.random().toString(36).substring(2, 15);
                        addTempImagePlaceholder(fullUrl, tempId);
                        
                        // Try to get the full-size image (the URL may already be full-size)
                        const fullSizeUrl = await getFullSizeImageUrl(fullUrl, baseUrl);
                        
                        // Replace placeholder with actual image
                        updateOrAddImageInGallery(fullUrl, fullSizeUrl, tempId);
                        
                        imageUrls.push(fullSizeUrl);
                    } catch (error) {
                        console.error(`Error processing image link ${fullUrl}:`, error);
                    }
                }
            }
        }
        
        return imageUrls;
    }

    // Function to extract non-image links from HTML for crawling
    function extractNonImageLinksFromHtml(htmlContent, baseUrl) {
        const parser = new DOMParser();
        const doc = parser.parseFromString(htmlContent, 'text/html');
        
        const links = Array.from(doc.querySelectorAll('a'));
        const nonImageLinks = [];
        
        for (const link of links) {
            let href = link.getAttribute('href');
            
            if (href) {
                const fullUrl = getAbsoluteUrl(baseUrl, href);
                
                // Skip if null, already processed, or is an image
                if (fullUrl && !processedPageUrls.has(fullUrl) && !isImageUrl(fullUrl)) {
                    // Skip external links and common unwanted paths
                    const urlObj = new URL(fullUrl);
                    if (urlObj.hostname === window.location.hostname && 
                        !fullUrl.includes('#') && 
                        !fullUrl.includes('logout') &&
                        !fullUrl.includes('login') &&
                        !fullUrl.includes('register') &&
                        !fullUrl.includes('signin') &&
                        !fullUrl.includes('signout') &&
                        !fullUrl.includes('auth') &&
                        !fullUrl.includes('account')) {
                        
                        nonImageLinks.push(fullUrl);
                    }
                }
            }
        }
        
        return nonImageLinks;
    }

    // Function to update the counter display
    function updateCounter() {
        statusCounter.textContent = `Found: ${foundImages.length} images from ${processedPageUrls.size} pages`;
    }

    // Function to process the next batch of links with dynamic updates
    async function processNextBatch() {
        if (pendingLinks.length === 0 || !isProcessing) {
            if (isProcessing) {
                // Finished processing all links
                statusCounter.textContent = `Completed: Found ${foundImages.length} images from ${processedPageUrls.size} pages`;
                isProcessing = false;
                
                // Show completion notification
                const completionNotice = document.createElement('div');
                completionNotice.style.cssText = `
                    position: fixed;
                    bottom: 20px;
                    right: 20px;
                    background: rgba(46, 204, 113, 0.9);
                    color: white;
                    padding: 10px 20px;
                    border-radius: 5px;
                    z-index: 10003;
                    animation: fadeOut 3s forwards 2s;
                `;
                completionNotice.textContent = `✓ Found ${foundImages.length} images`;
                
                const fadeOutStyle = document.createElement('style');
                fadeOutStyle.textContent = `
                    @keyframes fadeOut {
                        from { opacity: 1; }
                        to { opacity: 0; visibility: hidden; }
                    }
                `;
                document.head.appendChild(fadeOutStyle);
                document.body.appendChild(completionNotice);
                
                setTimeout(() => {
                    if (document.body.contains(completionNotice)) {
                        document.body.removeChild(completionNotice);
                    }
                }, 5000);
            }
            return;
        }
        
        // Take the next batch of links to process (up to 3 at a time)
        const batchSize = 3;
        const batch = pendingLinks.splice(0, batchSize);
        
        // Process each link in the batch
        const promises = batch.map(async (link) => {
            try {
                processedPageUrls.add(link);
                
                // Fetch the page content
                const response = await fetchUrl(link);
                
                // Extract images from the page
                await extractImagesFromHtml(response.responseText, link);
                
                // Find more links to follow
                if (processedPageUrls.size < 20) { // Limit crawl depth
                    const newLinks = extractNonImageLinksFromHtml(response.responseText, link);
                    
                    // Add new links to pending links, avoiding duplicates
                    for (const newLink of newLinks) {
                        if (!processedPageUrls.has(newLink) && !pendingLinks.includes(newLink)) {
                            pendingLinks.push(newLink);
                        }
                    }
                }
            } catch (error) {
                console.error(`Error processing link ${link}:`, error);
            }
        });
        
        // Wait for all links in this batch to be processed
        await Promise.all(promises);
        
        // Update the counter
        updateCounter();
        
        // Process the next batch after a short delay
        setTimeout(() => {
            processNextBatch();
        }, 300);
    }

    // Main function to start collecting images
    async function collectImages() {
        if (isProcessing) return;
        isProcessing = true;
        
        // Clear previous results
        imageGrid.innerHTML = '';
        foundImages = [];
        processedPageUrls = new Set();
        processedImageUrls = new Set();
        pendingLinks = [];
        imageGroups = new Map();
        
        statusCounter.textContent = 'Searching...';
        
        try {
            // First, collect images from current page
            const currentPageHtml = document.documentElement.outerHTML;
            const currentPageImages = await extractImagesFromHtml(currentPageHtml, window.location.href);
            
            // Mark current page as processed
            processedPageUrls.add(window.location.href);
            
            // Get links to follow (one level down)
            const links = extractNonImageLinksFromHtml(currentPageHtml, window.location.href);
            pendingLinks.push(...links);
            // Start processing batches
            processNextBatch();
        } catch (error) {
            console.error('Error collecting images:', error);
            statusCounter.textContent = 'Error: ' + error.message;
            isProcessing = false;
        }
    }

    // Filter images based on minimum width
    function filterImagesByMinWidth(minWidth) {
        // Convert elements to array for filtering
        const items = Array.from(imageGrid.children);
        
        items.forEach(item => {
            const img = item.querySelector('img');
            if (img && img.naturalWidth) {
                if (img.naturalWidth < minWidth) {
                    item.style.display = 'none';
                } else {
                    item.style.display = '';
                }
            }
        });
    }

    // Add event listeners
    floatingButton.addEventListener('click', () => {
        galleryContainer.style.display = 'flex';
        if (foundImages.length === 0) {
            collectImages();
        }
    });

    closeButton.addEventListener('click', () => {
        galleryContainer.style.display = 'none';
    });

    downloadAllButton.addEventListener('click', () => {
        foundImages.forEach((imageUrl, index) => {
            setTimeout(() => {
                let filename = imageUrl.split('/').pop().split('?')[0] || `image_${index}.jpg`;
                GM_download({
                    url: imageUrl,
                    name: filename
                });
            }, index * 500); // Delay to prevent browser throttling
        });
    });

    filterButton.addEventListener('click', () => {
        const minWidth = parseInt(minWidthInput.value);
        if (!isNaN(minWidth)) {
            filterImagesByMinWidth(minWidth);
        }
    });

    // Optional: Add keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        // Press Esc to close the gallery
        if (e.key === 'Escape' && galleryContainer.style.display === 'flex') {
            galleryContainer.style.display = 'none';
        }
        
        // Press Alt+I to open the gallery
        if (e.altKey && e.key === 'i') {
            galleryContainer.style.display = 'flex';
            if (foundImages.length === 0) {
                collectImages();
            }
        }
    });

    // Show a welcome message when the script first loads
    const welcomeMessage = document.createElement('div');
    welcomeMessage.style.cssText = `
        position: fixed;
        bottom: 20px;
        right: 20px;
        background: rgba(52, 152, 219, 0.9);
        color: white;
        padding: 15px;
        border-radius: 5px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.2);
        font-size: 14px;
        max-width: 300px;
        z-index: 9998;
        animation: fadeOut 3s forwards 5s;
    `;
    welcomeMessage.innerHTML = `
        <strong>Enhanced Image Collector Ready</strong><br>
        Click the 📷 button or press Alt+I to collect images from this page.
    `;
    
    const welcomeStyle = document.createElement('style');
    welcomeStyle.textContent = `
        @keyframes fadeOut {
            from { opacity: 1; }
            to { opacity: 0; visibility: hidden; }
        }
    `;
    document.head.appendChild(welcomeStyle);
    document.body.appendChild(welcomeMessage);
    
    setTimeout(() => {
        if (document.body.contains(welcomeMessage)) {
            document.body.removeChild(welcomeMessage);
        }
    }, 8000);
})();