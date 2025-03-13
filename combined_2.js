// ==UserScript==
// @name         Enhanced Image Collector with Persistence
// @namespace    http://tampermonkey.net/
// @version      2.0
// @description  Collect and view all images on a page with persistence support
// @author       JLSmart13
// @match        *://*/*
// @icon         https://www.google.com/s2/favicons?sz=64&domain=github.com
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_deleteValue
// @grant        GM_listValues
// @require      https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js
// ==/UserScript==

(function() {
    'use strict';

    // Main UI elements
    let galleryContainer;
    let imageGrid;
    let statusCounter;
    let floatingButton;
    let closeButton;
    let downloadButton;
    let crawlerButton;
    let crawlerControls;
    let pauseResumeButton;
    let stopButton;

    // Tracking variables
    let processedPageUrls = new Set();
    let processedImageUrls = new Set();
    let pendingLinks = [];
    let foundImages = [];
    let imageGroups = new Map();
    let isProcessing = false;
    let isCrawlerActive = false;
    let isCrawlerPaused = false;
    let crawlerStartTime = null;
    let lastProgressUpdate = null;
    let crawlerStats = {
        startTime: 0,
        lastActive: 0,
        pagesScanned: 0,
        imagesFound: 0,
        pendingLinksCount: 0,
        domainsCrawled: new Set()
    };

    // Persistence tracking
    let currentMethod = null;
    let imageResolutionFailures = [];

    // Initialize UI
    function createUI() {
        // Create floating button
        floatingButton = document.createElement('button');
        floatingButton.textContent = '🖼️';
        floatingButton.title = 'Collect Images';
        floatingButton.style.cssText = `
            position: fixed;
            bottom: 20px;
            right: 20px;
            width: 50px;
            height: 50px;
            border-radius: 25px;
            background: #3498db;
            color: white;
            border: none;
            font-size: 24px;
            cursor: pointer;
            z-index: 10000;
            box-shadow: 0 2px 5px rgba(0,0,0,0.3);
            display: flex;
            align-items: center;
            justify-content: center;
            transition: background-color 0.3s;
            opacity: 0.8;
        `;

        floatingButton.addEventListener('mouseenter', () => {
            floatingButton.style.opacity = '1';
            floatingButton.style.backgroundColor = '#2980b9';
        });

        floatingButton.addEventListener('mouseleave', () => {
            floatingButton.style.opacity = '0.8';
            floatingButton.style.backgroundColor = '#3498db';
        });

        document.body.appendChild(floatingButton);

        // Create gallery container
        galleryContainer = document.createElement('div');
        galleryContainer.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.9);
            z-index: 10001;
            display: none;
            flex-direction: column;
            padding: 20px;
            box-sizing: border-box;
            color: white;
            font-family: Arial, sans-serif;
        `;

        // Add controls
        const controlsDiv = document.createElement('div');
        controlsDiv.className = 'gallery-controls';
        controlsDiv.style.cssText = `
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            flex-wrap: wrap;
        `;

        // Add title
        const galleryTitle = document.createElement('h2');
        galleryTitle.textContent = 'Images Found';
        galleryTitle.style.margin = '0';
        controlsDiv.appendChild(galleryTitle);

        // Add buttons container
        const buttonsDiv = document.createElement('div');
        buttonsDiv.style.display = 'flex';
        buttonsDiv.style.gap = '10px';
        buttonsDiv.style.alignItems = 'center';
        controlsDiv.appendChild(buttonsDiv);        // Create close button
        closeButton = document.createElement('button');
        closeButton.textContent = '✖️';
        closeButton.title = 'Close Gallery';
        closeButton.style.cssText = `
            background: #e74c3c;
            color: white;
            border: none;
            border-radius: 3px;
            padding: 5px 10px;
            cursor: pointer;
        `;

        closeButton.addEventListener('click', () => {
            galleryContainer.style.display = 'none';
        });
        buttonsDiv.appendChild(closeButton);

        // Create download button
        downloadButton = document.createElement('button');
        downloadButton.textContent = '📥 Download All';
        downloadButton.title = 'Download All Images as ZIP';
        downloadButton.style.cssText = `
            background: #2ecc71;
            color: white;
            border: none;
            border-radius: 3px;
            padding: 5px 10px;
            cursor: pointer;
        `;

        downloadButton.addEventListener('click', downloadImagesAsZip);
        buttonsDiv.appendChild(downloadButton);

        // Create crawler button
        crawlerButton = document.createElement('button');
        crawlerButton.textContent = '🕸️ Site Crawler';
        crawlerButton.title = 'Crawl entire site for images';
        crawlerButton.style.cssText = `
            background: #9b59b6;
            color: white;
            border: none;
            border-radius: 3px;
            padding: 5px 10px;
            cursor: pointer;
        `;

        buttonsDiv.appendChild(crawlerButton);

        galleryContainer.appendChild(controlsDiv);

        // Create crawler controls (hidden initially)
        crawlerControls = document.createElement('div');
        crawlerControls.style.cssText = `
            margin-bottom: 15px;
            display: none;
            flex-wrap: wrap;
            gap: 10px;
            align-items: center;
        `;

        // Create pause/resume button
        pauseResumeButton = document.createElement('button');
        pauseResumeButton.textContent = '⏸️ Pause';
        pauseResumeButton.style.cssText = `
            background: #f39c12;
            color: white;
            border: none;
            border-radius: 3px;
            padding: 5px 10px;
            cursor: pointer;
        `;

        pauseResumeButton.addEventListener('click', () => {
            if (isCrawlerPaused) {
                resumeCrawler();
            } else {
                pauseCrawler();
            }
        });

        crawlerControls.appendChild(pauseResumeButton);

        // Create stop button
        stopButton = document.createElement('button');
        stopButton.textContent = '⏹️ Stop';
        stopButton.style.cssText = `
            background: #e74c3c;
            color: white;
            border: none;
            border-radius: 3px;
            padding: 5px 10px;
            cursor: pointer;
        `;

        stopButton.addEventListener('click', () => {
            if (confirm('Stop the crawler? Progress will be saved.')) {
                isProcessing = false;
                isCrawlerPaused = false;
                isCrawlerActive = false;
                updateCounter();
                statusCounter.textContent += ' (Stopped)';
                saveCrawlerState(); // Save state when stopping
            }
        });

        crawlerControls.appendChild(stopButton);

        // Create status counter for crawler
        statusCounter = document.createElement('span');
        statusCounter.style.cssText = `
            font-size: 14px;
            color: white;
            margin-left: 10px;
        `;

        crawlerControls.appendChild(statusCounter);
        galleryContainer.appendChild(crawlerControls);

        // Create image grid
        imageGrid = document.createElement('div');
        imageGrid.style.cssText = `
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 10px;
            overflow-y: auto;
            padding: 10px;
            flex: 1;
        `;

        galleryContainer.appendChild(imageGrid);
        document.body.appendChild(galleryContainer);
    }    // Function to add an image to the gallery
    function addImageToGallery(imageUrl, fullSizeUrl) {
        if (!imageUrl) return;

        // Check if we already have this image
        if (foundImages.includes(imageUrl)) return;

        // Add to the list of found images
        foundImages.push(imageUrl);

        // Create group for full-size tracking
        if (fullSizeUrl && fullSizeUrl !== imageUrl) {
            // Create or update image group
            if (!imageGroups.has(fullSizeUrl)) {
                imageGroups.set(fullSizeUrl, new Set());
            }
            imageGroups.get(fullSizeUrl).add(imageUrl);
        }

        // Create image container
        const imgContainer = document.createElement('div');
        imgContainer.className = 'gallery-img-container';
        imgContainer.style.cssText = `
            background: #333;
            border-radius: 5px;
            overflow: hidden;
            position: relative;
            aspect-ratio: 1/1;
            display: flex;
            align-items: center;
            justify-content: center;
        `;

        // Create image element
        const img = document.createElement('img');
        img.loading = 'lazy';
        img.style.cssText = `
            max-width: 100%;
            max-height: 100%;
            object-fit: contain;
            cursor: pointer;
        `;

        // Show loading state
        // Show loading state with a valid base64-encoded SVG
        // Set the source and add error handling

        img.src = 'https://via.placeholder.com/150';


        // Set the source and add error handling
        setTimeout(() => {
            img.onerror = () => {
                // Handle error - replace with placeholder
                img.src = 'https://via.placeholder.com/150';
                imgContainer.style.backgroundColor = '#433';
            };

            img.onload = () => {
                // Handle successful load
                img.style.opacity = '1';
            };

            // Set actual src after brief delay (helps with layout)
            img.src = imageUrl;
        }, 50);



        // Add image click to open full size
        img.addEventListener('click', () => {
            window.open(fullSizeUrl || imageUrl, '_blank');
        });

        // Add image to container
        imgContainer.appendChild(img);

        // Add size info
        const sizeInfo = document.createElement('div');
        sizeInfo.style.cssText = `
            position: absolute;
            bottom: 0;
            right: 0;
            background: rgba(0,0,0,0.7);
            padding: 2px 5px;
            font-size: 10px;
        `;

        // Add info button
        const infoButton = document.createElement('button');
        infoButton.textContent = 'ℹ️';
        infoButton.title = 'Image Information';
        infoButton.style.cssText = `
            position: absolute;
            top: 5px;
            right: 5px;
            background: rgba(0,0,0,0.5);
            color: white;
            border: none;
            border-radius: 3px;
            width: 20px;
            height: 20px;
            font-size: 12px;
            cursor: pointer;
            padding: 0;
            display: flex;
            align-items: center;
            justify-content: center;
        `;

        infoButton.addEventListener('click', (e) => {
            e.stopPropagation();
            // Show image info popup
            showImageInfo(imageUrl, fullSizeUrl);
        });

        imgContainer.appendChild(infoButton);
        imgContainer.appendChild(sizeInfo);

        // Get image dimensions
        const tempImg = new Image();
        tempImg.onload = function() {
            sizeInfo.textContent = `${this.width}×${this.height}`;
        };
        tempImg.src = imageUrl;        // Add the image container to the grid
        imageGrid.appendChild(imgContainer);

        // Update counter
        updateCounter();
    }

    // Show image info popup
    function showImageInfo(imageUrl, fullSizeUrl) {
        const popup = document.createElement('div');
        popup.style.cssText = `
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: #333;
            padding: 20px;
            border-radius: 5px;
            z-index: 10003;
            max-width: 90%;
            width: 500px;
            color: white;
            box-shadow: 0 0 20px rgba(0,0,0,0.5);
        `;

        // Create close button
        const closePopup = document.createElement('button');
        closePopup.textContent = '✖';
        closePopup.style.cssText = `
            position: absolute;
            top: 10px;
            right: 10px;
            background: transparent;
            color: white;
            border: none;
            font-size: 16px;
            cursor: pointer;
        `;

        closePopup.onclick = () => {
            document.body.removeChild(popup);
        };

        // Create content
        let content = `
            <h3 style="margin-top:0">Image Information</h3>
            <div style="margin-bottom:15px">
                <img src="${imageUrl}" style="max-width:100%; max-height:200px; margin-bottom:10px; background:#222;">
                <div style="overflow-wrap:break-word; font-size:12px;">
                    <strong>URL:</strong> ${imageUrl}
                </div>
            </div>
        `;

        // Add full size info if different
        if (fullSizeUrl && fullSizeUrl !== imageUrl) {
            content += `
                <div style="margin-bottom:15px">
                    <strong>Full Size URL:</strong>
                    <div style="overflow-wrap:break-word; font-size:12px;">${fullSizeUrl}</div>
                </div>
            `;
        }

        // Add buttons
        content += `
            <div style="display:flex; gap:10px; margin-top:15px;">
                <button id="copyImgUrl" style="flex:1; padding:5px; background:#3498db; color:white; border:none; border-radius:3px; cursor:pointer;">
                    Copy URL
                </button>
                <button id="openImgUrl" style="flex:1; padding:5px; background:#2ecc71; color:white; border:none; border-radius:3px; cursor:pointer;">
                    Open Image
                </button>
            </div>
        `;

        popup.innerHTML = content;
        popup.appendChild(closePopup);
        document.body.appendChild(popup);

        // Add button functionality
        document.getElementById('copyImgUrl').addEventListener('click', () => {
            const urlToCopy = fullSizeUrl || imageUrl;
            navigator.clipboard.writeText(urlToCopy).then(() => {
                const btn = document.getElementById('copyImgUrl');
                const originalText = btn.textContent;
                btn.textContent = 'Copied!';
                setTimeout(() => {
                    btn.textContent = originalText;
                }, 1000);
            });
        });

        document.getElementById('openImgUrl').addEventListener('click', () => {
            window.open(fullSizeUrl || imageUrl, '_blank');
        });

        // Add key handlers
        const handleKeyDown = (e) => {
            if (e.key === 'Escape') {
                document.body.removeChild(popup);
                document.removeEventListener('keydown', handleKeyDown);
            }
        };
        document.addEventListener('keydown', handleKeyDown);
    }

    // Placeholder creator
    function createImagePlaceholder(id) {
        const imgContainer = document.createElement('div');
        imgContainer.id = id;
        imgContainer.className = 'gallery-img-container placeholder';
        imgContainer.style.cssText = `
            background: #444;
            border-radius: 5px;
            overflow: hidden;
            position: relative;
            aspect-ratio: 1/1;
            display: flex;
            align-items: center;
            justify-content: center;
        `;

        // Add loading spinner
        imgContainer.innerHTML = `
            <div style="width:32px; height:32px;">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="100%" height="100%">
                    <circle cx="12" cy="12" r="10" fill="none" stroke="#999" stroke-width="2" opacity="0.3"/>
                    <path fill="#fff" d="M12 2a10 10 0 0 1 10 10h-2a8 8 0 0 0-8-8V2z">
                        <animateTransform attributeName="transform" attributeType="XML" type="rotate" from="0 12 12" to="360 12 12" dur="1s" repeatCount="indefinite"/>
                    </path>
                </svg>
            </div>
        `;        // Add to the grid
        imageGrid.appendChild(imgContainer);
        return imgContainer;
    }

    // Update placeholder with actual image
    function updateOrAddImageInGallery(originalUrl, fullSizeUrl, placeholderId) {
        if (!originalUrl) return;
        // If placeholder exists, update it
        if (placeholderId) {
            const placeholder = document.getElementById(placeholderId);
            if (placeholder) {
                // Remove placeholder from the DOM
                placeholder.parentNode.removeChild(placeholder);
            }
        }

        // Add the image to gallery
        addImageToGallery(originalUrl, fullSizeUrl);

        // Save images if persistence is enabled
        if (currentMethod) {
            saveCrawlerState();
        }
    }

    // Update the counter display
    function updateCounter() {
        if (!statusCounter) return;

        // Create method indicator if needed
        let methodText = '';
        if (currentMethod) {
            methodText = currentMethod === 'standard' ? 'Standard Mode' : 'Crawler Mode';
        }

        // Update status counter
        const counters = [
            `${foundImages.length} images found`,
            methodText ? `(${methodText})` : '',
            processedPageUrls.size > 1 ? `from ${processedPageUrls.size} pages` : ''
        ].filter(Boolean).join(' ');

        statusCounter.textContent = counters;
    }

    // Function to download all images as a ZIP file
    function downloadImagesAsZip() {
        // Create a new JSZip instance
        const zip = new JSZip();
        let processed = 0;
        let failed = 0;
        let totalSize = 0;

        // Create progress popup
        const popup = document.createElement('div');
        popup.style.cssText = `
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        background: #333;
        padding: 20px;
        border-radius: 5px;
        z-index: 10003;
        width: 300px;
        color: white;
        text-align: center;
    `;

        popup.innerHTML = `
        <h3>Preparing Download...</h3>
        <div id="zipProgress" style="width:100%; height:20px; background:#555; border-radius:10px; overflow:hidden; margin:15px 0;">
            <div id="zipProgressBar" style="height:100%; width:0%; background:#3498db; transition:width 0.3s;"></div>
        </div>
        <div id="zipStatus">Fetching images... (0/${foundImages.length})</div>
    `;

        document.body.appendChild(popup);

        // Update progress display
        const updateProgress = () => {
            const total = foundImages.length;
            const progress = (processed + failed) / total * 100;
            document.getElementById('zipProgressBar').style.width = `${progress}%`;
            document.getElementById('zipStatus').textContent =
                `Fetching images... (${processed + failed}/${total}) - ${failed} failed - ${(totalSize / (1024 * 1024)).toFixed(1)}MB`;
        };

        // Process URLs and add to ZIP
        const processUrls = async () => {
            // Get all unique full-size URLs to download
            const urlsToDownload = new Set();

            // Add all found images
            foundImages.forEach(url => urlsToDownload.add(url));

            // For each group, keep only the full-size URL
            imageGroups.forEach((variants, fullSizeUrl) => {
                // Remove all variants from download list
                variants.forEach(url => urlsToDownload.delete(url));
                // Add the full-size version
                urlsToDownload.add(fullSizeUrl);
            });

            // Convert to array for processing
            const allUrls = [...urlsToDownload];

            // Process each URL
            for (const url of allUrls) {
                try {
                    // Get the image data
                    const response = await fetch(url, {credentials: 'omit'});
                    if (response.ok) {
                        const blob = await response.blob();
                        totalSize += blob.size;

                        // Create a unique filename
                        const filename = getUniqueFilename(url);

                        // Add to zip
                        zip.file(filename, blob);
                        processed++;
                    } else {
                        failed++;
                    }
                } catch (error) {
                    console.error('Error downloading image:', error);
                    failed++;
                }

                // Update progress
                updateProgress();
            }
        };        // Start processing images
        processUrls().then(() => {
            // Done fetching all images, generate ZIP
            if (processed > 0) {
                // Update status
                document.getElementById('zipStatus').textContent = 'Generating ZIP file...';

                // Generate the ZIP
                zip.generateAsync({
                    type: 'blob',
                    compression: 'DEFLATE',
                    compressionOptions: { level: 6 }
                }).then(content => {
                    // Create download link
                    const a = document.createElement('a');
                    const url = URL.createObjectURL(content);
                    a.href = url;

                    // Set filename with date/time
                    const now = new Date();
                    const timestamp = now.toISOString().replace(/[:.]/g, '-').slice(0, 19);
                    const domain = getDomain(window.location.href);

                    a.download = `images_${domain}_${timestamp}.zip`;
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);

                    // Update completion status
                    document.getElementById('zipStatus').innerHTML = `
                    <span style="color:#2ecc71">✓ ${processed} images downloaded (${(totalSize / (1024 * 1024)).toFixed(1)}MB)</span>
                    ${failed > 0 ? `<br><span style="color:#e74c3c">✗ ${failed} images failed</span>` : ''}
                    <br><br><button id="closeZipPopup" style="background:#3498db; border:none; color:white; padding:5px 15px; border-radius:3px; cursor:pointer">Close</button>
                `;

                // Add close button functionality
                document.getElementById('closeZipPopup').onclick = () => {
                    document.body.removeChild(popup);
                };
            });
        } else {
            // No images could be downloaded
            document.getElementById('zipStatus').innerHTML = `
                <span style="color:#e74c3c">✗ No images could be downloaded</span>
                <br><br><button id="closeZipPopup" style="background:#3498db; border:none; color:white; padding:5px 15px; border-radius:3px; cursor:pointer">Close</button>
            `;

            document.getElementById('closeZipPopup').onclick = () => {
                document.body.removeChild(popup);
            };
        }
    });
    }

    // Generate a unique filename for an image URL
    function getUniqueFilename(url) {
        try {
            // Parse URL
            const parsedUrl = new URL(url);
            // Get the pathname
            let pathname = parsedUrl.pathname;

            // Extract filename from path
            let filename = pathname.split('/').pop();

            // If no filename or no extension, create one
            if (!filename || !filename.includes('.')) {
                // Get extension from content type or default to jpg
                const ext = url.match(/\.([a-z0-9]{3,4})(?:$|\?)/i) ?
                      url.match(/\.([a-z0-9]{3,4})(?:$|\?)/i)[1] : 'jpg';

                // Create filename from URL parts
                const domain = parsedUrl.hostname.replace(/www\./i, '');
                const hash = Math.random().toString(36).substring(2, 10);
                filename = `${domain}_${hash}.${ext}`;
            }

            // Sanitize filename
            filename = filename.replace(/[/\\?%*:|"<>\s]/g, '_')
                .replace(/[&=]/g, '_')
                .toLowerCase();

            // Add random suffix if needed
            if (filename.length > 50) {
                const ext = filename.split('.').pop();
                filename = filename.substring(0, 40) + '_' +
                    Math.random().toString(36).substring(2, 7) +
                    '.' + ext;
            }

            return filename;
        } catch (e) {
            // Fallback for invalid URLs
            return `image_${Math.random().toString(36).substring(2, 10)}.jpg`;
        }
    }

    // Get the domain from a URL
    function getDomain(url) {
        try {
            const parsedUrl = new URL(url);
            return parsedUrl.hostname.replace(/www\./i, '');
        } catch (e) {
            return 'unknown';
        }
    }

    // Function to check if a URL might be an image
    function isImageUrl(url) {
        // Check file extension
        const extensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.svg', '.tiff'];
        const lowerUrl = url.toLowerCase();

        // Check for known file extensions in URL
        for (const ext of extensions) {
            if (lowerUrl.endsWith(ext) || lowerUrl.includes(ext + '?')) {
                return true;
            }
        }

        // Check for image patterns in URL
        const imagePatterns = [
            /\/image\//i, /\/img\//i, /\/thumb(nail)?s?\//i,
            /\/photos?\//i, /\/pictures?\//i
        ];

        for (const pattern of imagePatterns) {
            if (pattern.test(url)) {
                return true;
            }
        }

        return false;
    }

    // Get the base name of an image (for comparison)
    function getImageBaseName(url) {
        try {
            // Get just the filename from the URL
            const filename = url.split('/').pop().split('?')[0];

            // Remove extension
            const baseName = filename.replace(/\.[^.]+$/, '');

            // Remove common suffixes like _thumb, -small, etc.
            return baseName.replace(/_(?:thumb|small|medium|large|[0-9]+px)$/, '')
                .replace(/-(?:thumb|small|medium|large|[0-9]+px)$/, '');
        } catch (e) {
            return '';
        }
    }

    // Check if two URLs are on the same domain
    function isSameDomain(url1, url2) {
        try {
            const domain1 = new URL(url1).hostname;
            const domain2 = new URL(url2).hostname;
            return domain1 === domain2;
        } catch (e) {
            return false;
        }
    }

    // Log image resolution failures for debugging
    function logImageResolutionFailure(originalImage, sourcePage, pathFollowed, error) {
        // Create failure entry
        const failure = {
            originalImage,
            sourcePage,
            pathFollowed: pathFollowed || [],
            error: error || 'Unknown error',
            timestamp: Date.now()
        };

        // Add to failures list
        imageResolutionFailures.push(failure);

        // Save to storage if method is set
        if (currentMethod) {
            const logKey = `${getStorageKeyPrefix()}${currentMethod}_resolutionFailures`;
            saveToStorage(logKey, imageResolutionFailures);
        }

        // Show the failure log button if it exists
        if (window.failureLogButton) {
            window.failureLogButton.style.display = 'inline-block';
        }

        console.warn('Image resolution failure:', failure);
    }

    // Function to attempt to resolve a full-size image URL
    async function attemptToResolveFullSizeImage(imageUrl, pageUrl) {
        const result = {
            originalUrl: imageUrl,
            fullSizeUrl: imageUrl,
            success: false
        };

        // Maximum path length to follow
        const maxPathLength = 3;

        // Skip resolution if URL contains indicators it's already full-size
        const lowerUrl = imageUrl.toLowerCase();
        const fullSizeIndicators = ['full', 'original', 'large', 'high', 'orig', 'max'];

        for (const indicator of fullSizeIndicators) {
            if (lowerUrl.includes(indicator)) {
                result.success = true;
                return result;
            }
        }

        // Path tracking for failure logging
        const pathFollowed = [];

        try {
            // Try modification patterns first (fastest)
            const modificationPatterns = [
                // Replace thumb indicators with full-size indicators
                { from: /(_|\-)(?:thumb|small|thumbnail|s|t)\./i, to: '.' },
                { from: /(_|\-)(?:thumb|small|thumbnail|s|t)(_|\-)/i, to: '$2' },
                { from: /_\d{2,3}x\d{2,3}\./i, to: '.' },

                // Replace size indicators with larger ones
                { from: /(_|\-)(?:medium|m)(_|\-|\.)/, to: '$1large$2' },
                { from: /(_|\-)[sm](_|\-|\.)/, to: '$1l$2' },
                { from: /\/(?:thumb|small|thumbnails)\//i, to: '/large/' },
                { from: /\/(?:thumb|small|thumbnails)\//i, to: '/original/' },

                // Common size patterns in URLs
                { from: /\b(\d{2,3})x(\d{2,3})\b/i, to: '1200x1200' },
                { from: /[_-]w(\d{2,3})[_-]/i, to: '_w1200_' },
                { from: /[_-]h(\d{2,3})[_-]/i, to: '_h1200_' },

                // Common specific hosting site patterns
                { from: /\/(?:thumbs|t)(\d+)\./, to: '/i$1.' }, // imgur pattern
                { from: /\?size=\w+$/, to: '' }                 // remove size parameters


            ];

            // Try each pattern
            for (const pattern of modificationPatterns) {
                if (pattern.from.test(imageUrl)) {
                    const modifiedUrl = imageUrl.replace(pattern.from, pattern.to);

                    // Track this attempt
                    pathFollowed.push({
                        type: 'URL Pattern Modification',
                        url: modifiedUrl,
                        followed: true
                    });                    // Check if the modified URL works
                    try {
                        const response = await fetch(modifiedUrl, { method: 'HEAD', credentials: 'omit' });
                        if (response.ok) {
                            const contentType = response.headers.get('Content-Type');
                            if (contentType && contentType.startsWith('image/')) {
                                result.fullSizeUrl = modifiedUrl;
                                result.success = true;
                                return result;
                            }
                        }
                    } catch (e) {
                        // Pattern didn't work, try next one
                    }
                }
            }

            // Next, check if image is in a container page
            if (mightBeImageContainer(imageUrl)) {
                // Log this attempt
                pathFollowed.push({
                    type: 'Image Container Check',
                    url: imageUrl,
                    followed: true
                });

                try {
                    // Try to fetch the page
                    const response = await fetch(imageUrl, { credentials: 'omit' });
                    if (response.ok) {
                        const html = await response.text();

                        // Look for high-resolution images in the HTML
                        const possibleFullSizeUrls = extractPossibleFullSizeImageUrls(
                            html, imageUrl, imageUrl
                        );

                        // Find the best match
                        if (possibleFullSizeUrls.length > 0) {
                            const bestMatch = selectBestImageUrl(possibleFullSizeUrls);

                            if (bestMatch) {
                                result.fullSizeUrl = bestMatch;
                                result.success = true;
                                return result;
                            }
                        }
                    }
                } catch (e) {
                    // Container page approach didn't work
                }
            }

            // Also check the source page for better versions
            if (pageUrl && pageUrl !== imageUrl) {
                // Log this attempt
                pathFollowed.push({
                    type: 'Source Page Check',
                    url: pageUrl,
                    followed: true
                });

                try {
                    // Try to fetch the page
                    const response = await fetch(pageUrl, { credentials: 'omit' });
                    if (response.ok) {
                        const html = await response.text();

                        // Look for high-resolution versions of this image
                        const possibleFullSizeUrls = extractPossibleFullSizeImageUrls(
                            html, pageUrl, imageUrl
                        );

                        // Find the best match
                        if (possibleFullSizeUrls.length > 0) {
                            const bestMatch = selectBestImageUrl(possibleFullSizeUrls);

                            if (bestMatch) {
                                result.fullSizeUrl = bestMatch;
                                result.success = true;
                                return result;
                            }
                        }
                    }
                } catch (e) {
                    // Source page approach didn't work
                }
            }

            // If all attempts failed, use the original URL
            return result;

        } catch (e) {
            // Log the failure
            logImageResolutionFailure(imageUrl, pageUrl, pathFollowed, e.message);
            return result;
        }
    }

    // Create failure log button
    function createFailureLogButton() {
        // Create button
        window.failureLogButton = document.createElement('button');
        window.failureLogButton.textContent = '⚠️ Resolution Failures';
        window.failureLogButton.title = 'Show image resolution failures';
        window.failureLogButton.style.cssText = `
        background: #e67e22;
        color: white;
        border: none;
        border-radius: 3px;
        padding: 5px 10px;
        cursor: pointer;
        display: none;
        margin-left: 10px;
    `;

    window.failureLogButton.addEventListener('click', showImageResolutionFailures);

    // Add to crawler controls
    if (crawlerControls) {
        crawlerControls.appendChild(window.failureLogButton);
    }
}

    // Show image resolution failures
    function showImageResolutionFailures() {
        // Create popup
        const popup = document.createElement('div');
        popup.style.cssText = `
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        background: #333;
        padding: 20px;
        border-radius: 5px;
        z-index: 10003;
        width: 80%;
        max-width: 800px;
        height: 80%;
        max-height: 600px;
        color: white;
        overflow: auto;
        box-shadow: 0 0 20px
        rgba(0,0,0,0.5);
    `;

    // Add close button
    const closeButton = document.createElement('button');
    closeButton.textContent = '✖';
    closeButton.style.cssText = `
        position: absolute;
        top: 10px;
        right: 10px;
        background: transparent;
        color: white;
        border: none;
        font-size: 16px;
        cursor: pointer;
    `;

    closeButton.addEventListener('click', () => {
        document.body.removeChild(popup);
    });

    popup.appendChild(closeButton);

    // Create content
    const content = document.createElement('div');

    // Add header
    content.innerHTML = `
        <h3>Image Resolution Failures (${imageResolutionFailures.length})</h3>
        <div style="margin-bottom:15px;">
            These are images where high-resolution versions could not be found.
        </div>
    `;

    // Add each failure
    for (const failure of imageResolutionFailures) {
        const failureEntry = document.createElement('div');
        failureEntry.style.cssText = `
            margin-bottom: 20px;
            padding: 10px;
            background: #444;
            border-radius: 5px;
        `;

        // Format timestamp
        const date = new Date(failure.timestamp);
        const timeStr = date.toLocaleString();

        // Create entry HTML
        failureEntry.innerHTML = `
            <div style="margin-bottom:5px;">
                <strong>Original Image:</strong>
                <a href="${failure.originalImage}" target="_blank" style="color:#3498db; word-break:break-all;">${failure.originalImage}</a>
            </div>
            <div style="margin-bottom:5px;">
                <strong>Source Page:</strong>
                <a href="${failure.sourcePage}" target="_blank" style="color:#3498db; word-break:break-all;">${failure.sourcePage}</a>
            </div>
            <div style="margin-bottom:5px;">
                <strong>Error:</strong> <span style="color:#e74c3c;">${failure.error}</span>
            </div>
            <div style="margin-bottom:5px;">
                <strong>Time:</strong> ${timeStr}
            </div>
            <div style="margin-top:10px;">
                <button class="show-path-btn" style="background:#7f8c8d; color:white; border:none; border-radius:3px; padding:3px 8px; cursor:pointer;">
                    Show Resolution Path
                </button>
                <div class="path-details" style="display:none; margin-top:10px; padding:5px; background:#555; border-radius:3px; font-size:12px;"></div>
            </div>
        `;

        content.appendChild(failureEntry);

        // Add path button functionality
        const pathBtn = failureEntry.querySelector('.show-path-btn');
        const pathDetails = failureEntry.querySelector('.path-details');

        pathBtn.addEventListener('click', () => {
            // Toggle visibility
            const isHidden = pathDetails.style.display === 'none';
            pathDetails.style.display = isHidden ? 'block' : 'none';
            pathBtn.textContent = isHidden ? 'Hide Resolution Path' : 'Show Resolution Path';

            // Only build path details once
            if (isHidden && pathDetails.children.length === 0 && failure.pathFollowed) {
                // Create path steps
                let pathHTML = '<ol style="margin:0; padding-left:20px;">';

                for (const step of failure.pathFollowed) {
                    pathHTML += `
                        <li style="margin-bottom:5px;">
                            <div><strong>${step.type}:</strong></div>
                            <div style="word-break:break-all;">${step.url}</div>
                            <div style="color:${step.followed ? '#2ecc71' : '#e74c3c'}; font-style:italic;">
                                ${step.followed ? '✓ Attempted' : '✗ Skipped'}
                            </div>
                        </li>
                    `;
                }

                pathHTML += '</ol>';
                pathDetails.innerHTML = pathHTML;
            }
        });
    }

    // Add clear button
    const clearButton = document.createElement('button');
    clearButton.textContent = '🗑️ Clear All Failures';
    clearButton.style.cssText = `
        background: #e74c3c;
        color: white;
        border: none;
        border-radius: 3px;
        padding: 5px 10px;
        cursor: pointer;
        margin-top: 20px;
    `;

    clearButton.addEventListener('click', () => {
        if (confirm('Clear all resolution failures? This cannot be undone.')) {
            imageResolutionFailures = [];

            // Save empty array to storage
            if (currentMethod) {
                const logKey = `${getStorageKeyPrefix()}${currentMethod}_resolutionFailures`;
                saveToStorage(logKey, []);
            }

            // Hide failure log button
            if (window.failureLogButton) {
                window.failureLogButton.style.display = 'none';
            }

            // Close the popup
            document.body.removeChild(popup);
        }
    });

    content.appendChild(clearButton);
    popup.appendChild(content);
    document.body.appendChild(popup);
}

    // Function to add an event listener to start image collection
    function setupEventListeners() {
        floatingButton.addEventListener('click', () => {
            galleryContainer.style.display = 'flex';
            startImageCollection();
        });

        crawlerButton.addEventListener('click', () => {
            if (confirm('Start the site crawler? This will scan the entire site for images.')) {
                startSiteCrawler();
            }
        });
    }

    // Start the image collection process
    function startImageCollection() {
        if (isProcessing) return;
        isProcessing = true;

        // Reset previous state
        processedPageUrls.clear();
        processedImageUrls.clear();
        pendingLinks = [];
        foundImages = [];
        imageGroups.clear();

        // Set method to standard
        setCurrentMethod('standard');

        // Collect images from current page
        collectImagesFromPage(window.location.href, document);

        isProcessing = false;
    }

    // Start the site crawler process
    function startSiteCrawler() {
        if (isProcessing) return;
        isProcessing = true;

        // Reset previous state
        processedPageUrls.clear();
        processedImageUrls.clear();
        pendingLinks = [];
        foundImages = [];
        imageGroups.clear();

        // Set method to crawler
        setCurrentMethod('crawler');

        // Initialize crawler stats
        crawlerStats = {
            startTime: Date.now(),
            lastActive: Date.now(),
            pagesScanned: 0,
            imagesFound: 0,
            pendingLinksCount: 0,
            domainsCrawled: new Set()
        };

        // Add initial page to pending links
        pendingLinks.push(window.location.href);

        // Process pending links
        processPendingLinks();
    }

    // Process pending links in site crawler
    async function processPendingLinks() {
        while (pendingLinks.length > 0) {
            if (isCrawlerPaused || !isCrawlerActive) break;

            const link = pendingLinks.shift();
            if (!link || processedPageUrls.has(link)) continue;

            // Mark URL as processed
            processedPageUrls.add(link);

            // Fetch and process the page
            try {
                const response = await fetch(link, {credentials: 'omit'});
                const html = await response.text();
                const parser = new DOMParser();
                const doc = parser.parseFromString(html, 'text/html');

                // Collect images from the page
                collectImagesFromPage(link, doc);

                // Collect links from the page
                collectLinksFromPage(link, doc);

                // Update crawler stats
                crawlerStats.pagesScanned++;
                crawlerStats.lastActive = Date.now();
                updateCrawlerProgress();
            } catch (error) {
                console.error('Error processing link:', error);
            }
        }

        isProcessing = false;
    }

    // Collect images from a page
    function collectImagesFromPage(pageUrl, doc) {
        const images = doc.querySelectorAll('img');
        images.forEach(img => {
            const src = img.getAttribute('src');
            if (src && !processedImageUrls.has(src)) {
                processedImageUrls.add(src);

                // Attempt to resolve full-size image
                attemptToResolveFullSizeImage(src, pageUrl).then(result => {
                    if (result.success) {
                        updateOrAddImageInGallery(src, result.fullSizeUrl);
                    } else {
                        logImageResolutionFailure(src, pageUrl, result.pathFollowed, 'Resolution failed');
                    }
                });
            }
        });

        // Update found images count
        updateCounter();
    }

    // Collect links from a page
    function collectLinksFromPage(pageUrl, doc) {
        const links = doc.querySelectorAll('a[href]');
        links.forEach(link => {
            const href = link.getAttribute('href');
            if (href && !processedPageUrls.has(href) && isSameDomain(pageUrl, href)) {
                pendingLinks.push(href);
            }
        });

        // Update pending links count
        crawlerStats.pendingLinksCount = pendingLinks.length;
        updateCrawlerProgress();
    }

    // Update crawler progress UI
    function updateCrawlerProgress() {
        const progress = document.querySelector('#crawlerProgress');
        const progressBar = progress.querySelector('.progress-bar');

        const totalLinks = crawlerStats.pagesScanned + crawlerStats.pendingLinksCount;
        const progressPercent = totalLinks > 0 ? (crawlerStats.pagesScanned / totalLinks) * 100 : 0;

        progressBar.style.width = `${progressPercent}%`;
        progress.querySelector('.progress-text').textContent = `Scanned ${crawlerStats.pagesScanned} pages, ${crawlerStats.pendingLinksCount} pending`;

        // Save crawler state
        saveCrawlerState();
    }

})();
// End of the script