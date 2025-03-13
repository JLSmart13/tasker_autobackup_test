// ==UserScript==
// @name         Enhanced Image Collector with Persistence
// @namespace    http://tampermonkey.net/
// @version      3.0
// @description  Collect and view all images on a page with specialized scraping for various sites
// @author       JLSmart13
// @match        *://*/*
// @icon         https://www.google.com/s2/favicons?sz=64&domain=github.com
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_deleteValue
// @grant        GM_listValues
// @require      https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js
// ==/UserScript==

(function () {
  'use strict';
  // Initialize function - Call this first
  function init() {
    createUI();
    setupEventListeners();
    createFailureLogButton();
  }

  // Main UI elements
  let galleryContainer;
  let imageGrid;
  let statusCounter;
  let floatingButton;
  let closeButton;
  let downloadButton;
  let standardModeButton; // New button for standard mode
  let crawlerButton;
  let standardControls; // New container for standard mode controls
  let crawlerControls;
  let pauseResumeButton;
  let stopButton;
  let modeSwitcher; // New mode switcher UI element

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

  // Hierarchical structure for organization
  let imageHierarchy = {
    boards: new Map(), // Map of board name -> Map of threads
  };

  // Persistence tracking
  let currentMethod = null;
  let imageResolutionFailures = [];
  
  // Site-specific settings
  const siteSettings = {
    'anonib.pk': {
      isBoardSite: true,
      boardSelector: 'ul.list-boards a',
      threadSelector: 'a.linkThumb',
      threadTitleSelector: 'a.linkName',
      imageSelector: 'a.file-link',
      catalogPath: '/catalog.html',
      thumbnailPrefix: 't_'
    },
    'pornpics.com': {
      isCatalogSite: true,
      catalogSelector: '.thumb-list a',
      gallerySelector: '.gallery__image-wrapper img',
      thumbsSelector: '.rel-link img',
      paginationSelector: '.pagination a'
    }
  };

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

    // Add mode switcher
    modeSwitcher = document.createElement('div');
    modeSwitcher.style.cssText = `
    display: flex;
    margin-left: auto;
    margin-right: 20px;
    background: #444;
    border-radius: 5px;
    overflow: hidden;
    `;
    
    // Add buttons container
    const buttonsDiv = document.createElement('div');
    buttonsDiv.style.display = 'flex';
    buttonsDiv.style.gap = '10px';
    buttonsDiv.style.alignItems = 'center';
    controlsDiv.appendChild(buttonsDiv);
    
    // Create close button
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

    // Create standard mode button
    standardModeButton = document.createElement('button');
    standardModeButton.textContent = '🔍 Standard Mode';
    standardModeButton.title = 'Collect images from current page only';
    standardModeButton.style.cssText = `
    background: #3498db;
    color: white;
    border: none;
    border-radius: 3px;
    padding: 5px 10px;
    cursor: pointer;
    `;

    standardModeButton.addEventListener('click', () => {
      switchModes('standard');
      startImageCollection();
    });
    
    buttonsDiv.appendChild(standardModeButton);

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

    crawlerButton.addEventListener('click', () => {
      if (confirm('Start the site crawler? This will scan the entire site for images.')) {
        switchModes('crawler');
        startSiteCrawler();
      }
    });

    buttonsDiv.appendChild(crawlerButton);

    galleryContainer.appendChild(controlsDiv);

    // Create standard mode controls (initially shown)
    standardControls = document.createElement('div');
    standardControls.style.cssText = `
    margin-bottom: 15px;
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    align-items: center;
    `;
    
    // Add refresh button for standard mode
    const refreshButton = document.createElement('button');
    refreshButton.textContent = '🔄 Refresh';
    refreshButton.title = 'Refresh images from current page';
    refreshButton.style.cssText = `
    background: #3498db;
    color: white;
    border: none;
    border-radius: 3px;
    padding: 5px 10px;
    cursor: pointer;
    `;
    
    refreshButton.addEventListener('click', startImageCollection);
    standardControls.appendChild(refreshButton);
    
    // Create status display for standard mode
    const standardStatusCounter = document.createElement('span');
    standardStatusCounter.style.cssText = `
    font-size: 14px;
    color: white;
    margin-left: 10px;
    `;
    standardStatusCounter.textContent = 'Standard Mode';
    standardControls.appendChild(standardStatusCounter);
    
    galleryContainer.appendChild(standardControls);

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
  }

  // Switch between standard and crawler modes
  function switchModes(mode) {
    currentMethod = mode;
    
    // Update UI based on selected mode
    if (mode === 'standard') {
      standardControls.style.display = 'flex';
      crawlerControls.style.display = 'none';
            standardModeButton.style.background = '#2980b9'; // Highlight active button
      crawlerButton.style.background = '#9b59b6'; // Reset crawler button color
    } else if (mode === 'crawler') {
      standardControls.style.display = 'none';
      crawlerControls.style.display = 'flex';
      standardModeButton.style.background = '#3498db'; // Reset standard button color
      crawlerButton.style.background = '#8e44ad'; // Highlight active button
      
      // Create crawler progress UI if it doesn't exist
      if (!document.getElementById('crawlerProgress')) {
        createCrawlerProgressUI();
      }
    }
    
    // Update gallery view based on mode
    updateGalleryView(mode);
  }
  
  // Update gallery view based on current mode
  function updateGalleryView(mode) {
    // Clear the image grid
    imageGrid.innerHTML = '';
    
    if (mode === 'standard') {
      // Standard view - simple grid of images
      foundImages.forEach(imageUrl => {
        const fullSizeUrl = getFullSizeUrl(imageUrl);
        addImageToGallery(imageUrl, fullSizeUrl);
      });
    } else if (mode === 'crawler') {
      // Hierarchical view for crawler mode
      if (isAnonibSite()) {
        createHierarchicalGalleryView();
      } else {
        // For other sites, use standard grid but maintain crawler controls
        foundImages.forEach(imageUrl => {
          const fullSizeUrl = getFullSizeUrl(imageUrl);
          addImageToGallery(imageUrl, fullSizeUrl);
        });
      }
    }
  }
  
  // Check if current site is anonib.pk
  function isAnonibSite() {
    return window.location.hostname.includes('anonib.pk');
  }
  
  // Check if current site is pornpics.com
  function isPornPicsSite() {
    return window.location.hostname.includes('pornpics.com');
  }
  
  // Get the full size URL for an image if available
  function getFullSizeUrl(imageUrl) {
    for (const [fullSizeUrl, variants] of imageGroups.entries()) {
      if (variants.has(imageUrl)) {
        return fullSizeUrl;
      }
    }
    return imageUrl;
  }
  
  // Create hierarchical gallery view for sites like anonib.pk
  function createHierarchicalGalleryView() {
    // Clear the grid first
    imageGrid.innerHTML = '';
    imageGrid.style.display = 'block'; // Change to block for hierarchical view
    
    // Create a container for the hierarchical view
    const hierarchyContainer = document.createElement('div');
    hierarchyContainer.className = 'hierarchy-container';
    hierarchyContainer.style.cssText = `
    width: 100%;
    padding: 10px;
    color: white;
    `;
    
    // Add boards to the view
    if (imageHierarchy.boards.size === 0) {
      // No hierarchical data available, show message
      const noDataMsg = document.createElement('div');
      noDataMsg.style.cssText = `
      text-align: center;
      padding: 20px;
      color: #999;
      font-style: italic;
      `;
      noDataMsg.textContent = 'No hierarchical data available. Run the crawler on anonib.pk to see organized boards and threads.';
      hierarchyContainer.appendChild(noDataMsg);
    } else {
      // Add each board
      for (const [boardName, threads] of imageHierarchy.boards.entries()) {
        const boardElement = createCollapsibleSection(boardName, 'h1');
        
        // Add threads under this board
        for (const [threadId, threadData] of threads.entries()) {
          const threadTitle = threadData.title || `Unnamed #${threadId}`;
          const threadElement = createCollapsibleSection(threadTitle, 'h2');
          
          // Create a grid for the images in this thread
          const threadGrid = document.createElement('div');
          threadGrid.style.cssText = `
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
          gap: 10px;
          margin: 10px 0;
          padding-left: 20px;
          `;
          
          // Add images for this thread
          if (threadData.images && threadData.images.length > 0) {
            threadData.images.forEach(imageUrl => {
              const imgContainer = document.createElement('div');
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
              
              const img = document.createElement('img');
              img.loading = 'lazy';
              img.style.cssText = `
              max-width: 100%;
              max-height: 100%;
              object-fit: contain;
              cursor: pointer;
              `;
              
              img.src = imageUrl;
              img.onclick = () => window.open(imageUrl, '_blank');
              
              imgContainer.appendChild(img);
              threadGrid.appendChild(imgContainer);
            });
          } else {
            // No images in this thread
            const noImages = document.createElement('div');
            noImages.style.cssText = `
            padding: 10px;
            color: #999;
            font-style: italic;
            grid-column: 1 / -1;
            `;
            noImages.textContent = 'No images found in this thread';
            threadGrid.appendChild(noImages);
          }
          
          threadElement.appendChild(threadGrid);
          boardElement.appendChild(threadElement);
        }
        
        hierarchyContainer.appendChild(boardElement);
      }
    }
    
    imageGrid.appendChild(hierarchyContainer);
  }
  
  // Create a collapsible section with a toggle
  function createCollapsibleSection(title, headerTag = 'h2') {
    const section = document.createElement('div');
    section.className = 'collapsible-section';
    section.style.cssText = `
    margin-bottom: 15px;
    border-radius: 5px;
    overflow: hidden;
    background: rgba(40, 40, 40, 0.7);
    `;
    
    const header = document.createElement(headerTag);
    header.className = 'collapsible-header';
    header.style.cssText = `
    padding: 10px 15px;
    margin: 0;
    background: rgba(60, 60, 60, 0.7);
    cursor: pointer;
    display: flex;
    justify-content: space-between;
    align-items: center;
    `;
    
    const headerText = document.createElement('span');
    headerText.textContent = title;
    
    const toggleIcon = document.createElement('span');
    toggleIcon.textContent = '▼';
    toggleIcon.style.transition = 'transform 0.3s';
    
    header.appendChild(headerText);
    header.appendChild(toggleIcon);
    
    const content = document.createElement('div');
    content.className = 'collapsible-content';
    content.style.cssText = `
    padding: 0 15px 15px;
    `;
    
    // Add toggle functionality
    header.addEventListener('click', () => {
      if (content.style.display === 'none') {
        content.style.display = 'block';
        toggleIcon.style.transform = 'rotate(0deg)';
      } else {
        content.style.display = 'none';
        toggleIcon.style.transform = 'rotate(-90deg)';
      }
    });
    
    section.appendChild(header);
    section.appendChild(content);
    
    // Start expanded for h1, collapsed for others
    if (headerTag === 'h1') {
      content.style.display = 'block';
      toggleIcon.style.transform = 'rotate(0deg)';
    } else {
      content.style.display = 'none';
      toggleIcon.style.transform = 'rotate(-90deg)';
    }
    
    return section;
  }

  // Function to add an image to the gallery
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

    // Show loading state with a valid base64-encoded SVG
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
    tempImg.onload = function () {
      sizeInfo.textContent = `${this.width}×${this.height}`;
    };
    tempImg.src = imageUrl;
    
    // Add the image container to the grid
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
    `;
    
    // Add to the grid
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
    const zip = new JSZip();
    // Create a new JSZip instance
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
          const response = await fetch(url, { credentials: 'omit' });
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
    };
    
    // Start processing images
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

    // Handle AnonIB specific image resolution
    if (imageUrl.includes('anonib') && imageUrl.includes('t_')) {
      const fullSizeUrl = imageUrl.replace('t_', '');
      try {
        const response = await fetch(fullSizeUrl, { method: 'HEAD', credentials: 'omit' });
        if (response.ok) {
          result.fullSizeUrl = fullSizeUrl;
          result.success = true;
          return result;
        }
      } catch (e) {
        // Continue with normal resolution if this fails
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
          });
          
          // Check if the modified URL works
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
    switchModes('standard');

    // Collect images from current page
    collectImagesFromPage(window.location.href, document);

    isProcessing = false;
  }

  // Add this helper function to check if a URL is valid
  function isValidUrl(url) {
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  }
  
  // Start site crawler
  function startSiteCrawler() {
    if (isProcessing) return;
    isProcessing = true;
    isCrawlerActive = true;

    // Show crawler controls
    if (crawlerControls) {
      crawlerControls.style.display = 'flex';
    }

    // Reset previous state
    processedPageUrls.clear();
    processedImageUrls.clear();
    pendingLinks = [];
    foundImages = [];
    imageGroups.clear();
    
    // Reset hierarchy
    imageHierarchy.boards = new Map();

    // Set method to crawler
    setCurrentMethod('crawler');
    switchModes('crawler');

    // Initialize crawler stats
    crawlerStats = {
      startTime: Date.now(),
      lastActive: Date.now(),
      pagesScanned: 0,
      imagesFound: 0,
      pendingLinksCount: 0,
      domainsCrawled: new Set([getDomain(window.location.href)]) // Initialize with current domain
    };

    // For anonib.pk, use specialized crawling logic
    if (isAnonibSite()) {
      startAnonibCrawler();
      return;
    }
    
    // For pornpics.com, use specialized crawling logic
    if (isPornPicsSite()) {
      startPornPicsCrawler();
      return;
    }

    // Add initial page to pending links
    pendingLinks.push(window.location.href);

    // Create crawler progress UI if it doesn't exist
    if (!document.getElementById('crawlerProgress')) {
      createCrawlerProgressUI();
    }

    // Update initial progress
    updateCrawlerProgress();

    // Process pending links
    processPendingLinks();
  }

  // Specialized crawler for anonib.pk
  async function startAnonibCrawler() {
    // Update status
    statusCounter.textContent = "Starting AnonIB crawler...";
    
    try {
      // Step 1: Get all boards from the main page
      const response = await fetch(window.location.href, { credentials: 'omit' });
      if (!response.ok) throw new Error("Failed to fetch main page");
      
      const html = await response.text();
      const parser = new DOMParser();
      const doc = parser.parseFromString(html, 'text/html');
      
      // Find all board links
      const boardLinks = [];
      const boardElements = doc.querySelectorAll('ul.list-boards a');
      
      // Organize boards by priority section
      const usaSection = [];
      const otherSections = [];
      const generalSection = [];
      
      let currentSection = otherSections;
      
      // Identify sections
      const sections = doc.querySelectorAll('h2.box-title');
      let foundUSA = false;
      let foundGeneral = false;
      
      for (const section of sections) {
        const sectionText = section.textContent.trim();
        if (sectionText === "USA") {
          foundUSA = true;
          foundGeneral = false;
        } else if (sectionText === "General Boards") {
          foundGeneral = true;
          foundUSA = false;
        }
        
        // Get all board links after this section until the next section
        let currentElement = section.nextElementSibling;
        while (currentElement && !currentElement.matches('h2.box-title')) {
          const boardLinks = currentElement.querySelectorAll('a');
          for (const link of boardLinks) {
            const href = link.getAttribute('href');
            if (href && href.startsWith('/') && href.includes('/')) {
              const boardName = href.split('/')[1];
              
              if (foundUSA) {
                usaSection.push({ url: href, name: boardName });
              } else if (foundGeneral) {
                generalSection.push({ url: href, name: boardName });
              } else {
                otherSections.push({ url: href, name: boardName });
              }
            }
          }
          currentElement = currentElement.nextElementSibling;
        }
      }
      
      // Order boards by priority: USA first, then other sections, general last
      const allBoardLinks = [...usaSection, ...otherSections, ...generalSection];
      
      // Process each board
      for (let i = 0; i < allBoardLinks.length; i++) {
        if (!isCrawlerActive) break;
        if (isCrawlerPaused) {
          await new Promise(resolve => {
            const checkPause = setInterval(() => {
              if (!isCrawlerPaused) {
                clearInterval(checkPause);
                resolve();
              }
            }, 1000);
          });
        }
        
        const boardData = allBoardLinks[i];
        const boardUrl = new URL(boardData.url, window.location.origin).href;
        const catalogUrl = new URL(boardData.url + 'catalog.html', window.location.origin).href;
        
        // Update status
        statusCounter.textContent = `Processing board ${i+1}/${allBoardLinks.length}: ${boardData.name}`;
        
        // Create board entry in hierarchy if it doesn't exist
        if (!imageHierarchy.boards.has(boardData.name)) {
          imageHierarchy.boards.set(boardData.name, new Map());
        }
        
        try {
          // Fetch the catalog
          const catalogResponse = await fetch(catalogUrl, { credentials: 'omit' });
          if (!catalogResponse.ok) continue;
          
          const catalogHtml = await catalogResponse.text();
          const catalogDoc = parser.parseFromString(catalogHtml, 'text/html');
          
          // Find all thread links
          const threadLinks = catalogDoc.querySelectorAll('a.linkThumb');
          
          // Process each thread
          for (let j = 0; j < threadLinks.length; j++) {
            if (!isCrawlerActive) break;
            if (isCrawlerPaused) {
              await new Promise(resolve => {
                const checkPause = setInterval(() => {
                  if (!isCrawlerPaused) {
                    clearInterval(checkPause);
                    resolve();
                  }
                }, 1000);
              });
            }
            
            const threadLink = threadLinks[j];
            const threadHref = threadLink.getAttribute('href');
            
            if (!threadHref) continue;
            
            let threadId = '';
            const threadIdMatch = threadHref.match(/\/res\/(\d+)\.html/);
            if (threadIdMatch && threadIdMatch[1]) {
              threadId = threadIdMatch[1];
            } else {
              threadId = `unknown_${j}`;
            }
            
            // Get thread URL
            const threadUrl = new URL(threadHref, window.location.origin).href;
            
            // Find the thread title
            let threadTitle = '';
            const threadContainer = threadLink.closest('.thread');
            if (threadContainer) {
              const nameElement = threadContainer.querySelector('a.linkName');
              if (nameElement) {
                threadTitle = nameElement.textContent.trim();
              }
            }
            
            if (!threadTitle) {
              threadTitle = `Unnamed #${threadId}`;
            }
            
            // Update status
            statusCounter.textContent = `Processing board ${i+1}/${allBoardLinks.length}: ${boardData.name} - Thread ${j+1}/${threadLinks.length}`;
            
            // Store thread data in board hierarchy
            const boardThreads = imageHierarchy.boards.get(boardData.name);
            
            if (!boardThreads.has(threadId)) {
              boardThreads.set(threadId, {
                title: threadTitle,
                url: threadUrl,
                images: []
              });
            }
            
            try {
              // Fetch the thread page
              const threadResponse = await fetch(threadUrl, { credentials: 'omit' });
              if (!threadResponse.ok) continue;
              
              const threadHtml = await threadResponse.text();
              const threadDoc = parser.parseFromString(threadHtml, 'text/html');
              
              // Find all images in thread
              const threadImages = [];
              const imageElements = threadDoc.querySelectorAll('a.file-link');
              
              for (const imgElement of imageElements) {
                const imgUrl = imgElement.getAttribute('href');
                if (!imgUrl) continue;
                
                const fullImgUrl = new URL(imgUrl, window.location.origin).href;
                
                // Skip thumbnails (starting with t_)
                if (fullImgUrl.includes('/t_')) {
                  // Extract the non-thumbnail version by removing t_
                  const fullSizeUrl = fullImgUrl.replace('/t_', '/');
                  threadImages.push(fullSizeUrl);
                  
                  // Add to found images list
                  if (!foundImages.includes(fullSizeUrl)) {
                    foundImages.push(fullSizeUrl);
                  }
                } else {
                  threadImages.push(fullImgUrl);
                  
                  // Add to found images list
                  if (!foundImages.includes(fullImgUrl)) {
                    foundImages.push(fullImgUrl);
                  }
                }
              }
              
              // Store images in thread data
              const threadData = boardThreads.get(threadId);
              threadData.images = threadImages;
              
              // Update crawler stats
              crawlerStats.pagesScanned++;
              crawlerStats.imagesFound = foundImages.length;
              crawlerStats.lastActive = Date.now();
              
              // Update progress
              updateCrawlerProgress();
              
              // Add a small delay to prevent overwhelming the server
              await new Promise(resolve => setTimeout(resolve, 500));
            } catch (threadError) {
              console.error('Error processing thread:', threadError);
              continue;
            }
          }
        } catch (catalogError) {
          console.error('Error processing catalog:', catalogError);
          continue;
        }
      }
      
      // Crawler finished
      isCrawlerActive = false;
      isProcessing = false;
      
      // Update UI to show hierarchical view
      updateGalleryView('crawler');
      
      // Show completion status
      statusCounter.textContent = `Completed! Scanned ${crawlerStats.pagesScanned} threads, found ${foundImages.length} images`;
      
    } catch (error) {
      console.error('AnonIB crawler error:', error);
      statusCounter.textContent = `Error: ${error.message}`;
      isCrawlerActive = false;
      isProcessing = false;
    }
  }

  // Specialized crawler for pornpics.com
  async function startPornPicsCrawler() {
    // Update status
    statusCounter.textContent = "Starting PornPics crawler...";
    
    try {
        // Level 1: Main page categories/galleries
        const response = await fetch(window.location.href, { credentials: 'omit' });
        if (!response.ok) throw new Error("Failed to fetch main page");

        const html = await response.text();
        const parser = new DOMParser();
        const doc = parser.parseFromString(html, 'text/html');

        // Find gallery links - thumbnails that lead to galleries
        const galleryLinks = doc.querySelectorAll('.thumb-list a');
        const galleryUrls = [];

        // Get up to 10 gallery URLs from the main page
        for (let i = 0; i < Math.min(10, galleryLinks.length); i++) {
            const href = galleryLinks[i].getAttribute('href');
            if (href) {
                const fullUrl = new URL(href, window.location.origin).href;
                galleryUrls.push(fullUrl);
            }
        }

        // Process each gallery (Level 2)
        for (let i = 0; i < galleryUrls.length; i++) {
            if (!isCrawlerActive) break;
            if (isCrawlerPaused) {
                await new Promise(resolve => {
                    const checkPause = setInterval(() => {
                        if (!isCrawlerPaused) {
                            clearInterval(checkPause);
                            resolve();
                        }
                    }, 1000);
                });
            }

            const galleryUrl = galleryUrls[i];
            statusCounter.textContent = `Processing gallery ${i + 1}/${galleryUrls.length}`;

            try {
                const galleryResponse = await fetch(galleryUrl, { credentials: 'omit' });
                if (!galleryResponse.ok) continue;

                const galleryHtml = await galleryResponse.text();
                const galleryDoc = parser.parseFromString(galleryHtml, 'text/html');

                // Find all full-size images in the gallery
                const galleryImages = galleryDoc.querySelectorAll('.gallery__image-wrapper img');

                for (const imgElement of galleryImages) {
                    const imgUrl = imgElement.getAttribute('src');
                    if (!imgUrl) continue;

                    const fullImgUrl = new URL(imgUrl, window.location.origin).href;

                    if (!foundImages.includes(fullImgUrl)) {
                        foundImages.push(fullImgUrl);
                    }
                }

                // Find related galleries (Level 3)
                const relatedLinks = galleryDoc.querySelectorAll('.rel-link');

                // Process up to 3 related galleries
                for (let j = 0; j < Math.min(3, relatedLinks.length); j++) {
                    if (!isCrawlerActive) break;

                    const relatedLink = relatedLinks[j].querySelector('a');
                    if (!relatedLink) continue;

                    const relatedHref = relatedLink.getAttribute('href');
                    if (!relatedHref) continue;

                    const relatedUrl = new URL(relatedHref, window.location.origin).href;
                    statusCounter.textContent = `Processing gallery ${i + 1}/${galleryUrls.length} - Related ${j + 1}/${Math.min(3, relatedLinks.length)}`;

                    try {
                        const relatedResponse = await fetch(relatedUrl, { credentials: 'omit' });
                        if (!relatedResponse.ok) continue;

                        const relatedHtml = await relatedResponse.text();
                        const relatedDoc = parser.parseFromString(relatedHtml, 'text/html');

                        // Find all full-size images in the related gallery
                        const relatedImages = relatedDoc.querySelectorAll('.gallery__image-wrapper img');

                        for (const imgElement of relatedImages) {
                            const imgUrl = imgElement.getAttribute('src');
                            if (!imgUrl) continue;

                            const fullImgUrl = new URL(imgUrl, window.location.origin).href;

                            if (!foundImages.includes(fullImgUrl)) {
                                foundImages.push(fullImgUrl);
                            }
                        }

                    } catch (relatedError) {
                        console.error('Error processing related gallery:', relatedError);
                        continue;
                    }

                    await new Promise(resolve => setTimeout(resolve, 300));
                }

                crawlerStats.pagesScanned++;
                crawlerStats.imagesFound = foundImages.length;
                crawlerStats.lastActive = Date.now();

                updateCrawlerProgress();

                await new Promise(resolve => setTimeout(resolve, 500));

            } catch (galleryError) {
                console.error('Error processing gallery:', galleryError);
                continue;
            }
        }

        isCrawlerActive = false;
        isProcessing = false;

        updateGalleryView('crawler');

        statusCounter.textContent = `Completed! Scanned ${crawlerStats.pagesScanned} galleries, found ${foundImages.length} images`;

    } catch (error) {
        console.error('PornPics crawler error:', error);
        statusCounter.textContent = `Error: ${error.message}`;
        isCrawlerActive = false;
        isProcessing = false;
    }
}

  // Process pending links for standard crawler
  async function processPendingLinks() {
    if (!isCrawlerActive) return;

    while (pendingLinks.length > 0 && isCrawlerActive) {
      if (isCrawlerPaused) {
        await new Promise(resolve => setTimeout(resolve, 1000));
        continue;
      }

      const link = pendingLinks.shift();
      if (!link || processedPageUrls.has(link) || !isValidUrl(link)) continue;

      try {
        // Mark URL as processed
        processedPageUrls.add(link);

        // Fetch and process the page
        const response = await fetch(link, {
          credentials: 'omit',
          headers: {
            'Accept': 'text/html'
          }
        });

        if (response.ok && response.headers.get('content-type')?.includes('text/html')) {
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
          crawlerStats.pendingLinksCount = pendingLinks.length;
          updateCrawlerProgress();
        }
      } catch (error) {
        console.error('Error processing link:', error);
      }

      // Add a small delay to prevent overwhelming the server
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    if (pendingLinks.length === 0 && isCrawlerActive) {
      // Crawler finished
      isCrawlerActive = false;
      isProcessing = false;
      const progress = document.getElementById('crawlerProgress');
      if (progress) {
        const progressText = progress.querySelector('.progress-text');
        if (progressText) {
          progressText.textContent = `Finished! Scanned ${crawlerStats.pagesScanned} pages, found ${foundImages.length} images`;
        }
      }
    }
  }

  // Collect images from a page
  function collectImagesFromPage(pageUrl, doc) {
    // Process based on site-specific settings
    if (isAnonibSite()) {
      collectAnonibImages(pageUrl, doc);
      return;
    }
    
    if (isPornPicsSite()) {
      collectPornPicsImages(pageUrl, doc);
      return;
    }
    
    // Default image collection logic
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
  
  // Special image collector for anonib
  function collectAnonibImages(pageUrl, doc) {
    // Find all file links (which should point to images)
    const fileLinks = doc.querySelectorAll('a.file-link');
    
    fileLinks.forEach(link => {
      const href = link.getAttribute('href');
      if (href && !processedImageUrls.has(href)) {
        processedImageUrls.add(href);
        
        // Convert to absolute URL
        let fullUrl = href;
        if (!href.startsWith('http')) {
          fullUrl = new URL(href, pageUrl).href;
        }
        
        // Check if it's a thumbnail (t_ prefix)
        if (fullUrl.includes('/t_')) {
          // Get the full size URL by removing t_
          const fullSizeUrl = fullUrl.replace('/t_', '/');
          updateOrAddImageInGallery(fullUrl, fullSizeUrl);
        } else {
          updateOrAddImageInGallery(fullUrl, fullUrl);
        }
      }
    });
    
    // Update found images count
    updateCounter();
  }
  
  // Special image collector for pornpics
  function collectPornPicsImages(pageUrl, doc) {
    // Look for gallery images
    const galleryImages = doc.querySelectorAll('.gallery__image-wrapper img');
    
    galleryImages.forEach(img => {
      const src = img.getAttribute('src');
      if (src && !processedImageUrls.has(src)) {
        processedImageUrls.add(src);
        
        // Convert to absolute URL
        let fullUrl = src;
        if (!src.startsWith('http')) {
          fullUrl = new URL(src, pageUrl).href;
        }
        
        // Add image (already full-size)
        updateOrAddImageInGallery(fullUrl, fullUrl);
      }
    });
    
    // Also look for thumbnails that might link to galleries
    const thumbLinks = doc.querySelectorAll('.thumb-list a img');
    
    thumbLinks.forEach(img => {
      const src = img.getAttribute('src');
      if (src && !processedImageUrls.has(src)) {
        processedImageUrls.add(src);
        
        // Convert to absolute URL
        let fullUrl = src;
        if (!src.startsWith('http')) {
          fullUrl = new URL(src, pageUrl).href;
        }
        
        // Try to find the full-size version
        attemptToResolveFullSizeImage(fullUrl, pageUrl).then(result => {
          if (result.success) {
            updateOrAddImageInGallery(fullUrl, result.fullSizeUrl);
          } else {
            // Add it anyway
            updateOrAddImageInGallery(fullUrl, fullUrl);
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
  
  // Update crawler progress
  function updateCrawlerProgress() {
    const progress = document.getElementById('crawlerProgress');
    if (!progress) return;

    const progressBar = progress.querySelector('.progress-bar');
    const progressText = progress.querySelector('.progress-text');
    if (!progressBar || !progressText) return;

    const totalLinks = crawlerStats.pagesScanned + crawlerStats.pendingLinksCount;
    const progressPercent = totalLinks > 0 ? (crawlerStats.pagesScanned / totalLinks) * 100 : 0;

    progressBar.style.width = `${progressPercent}%`;

    // Add more detailed status information
    const timeElapsed = Math.floor((Date.now() - crawlerStats.startTime) / 1000); // in seconds
    progressText.textContent = `Scanned: ${crawlerStats.pagesScanned} pages | Pending: ${crawlerStats.pendingLinksCount} | Images: ${foundImages.length} | Time: ${timeElapsed}s`;

    // Save crawler state
    saveCrawlerState();
  }

  // Function to check if a URL might be an image container page
  function mightBeImageContainer(url) {
    // Common patterns for image hosting/gallery pages
    const patterns = [
      /\/photo\//i,
      /\/image\//i,
      /\/gallery\//i,
      /\/album\//i,
      /viewer/i,
      /lightbox/i
    ];

    return patterns.some(pattern => pattern.test(url));
  }

  // Function to extract possible full-size image URLs from HTML
  function extractPossibleFullSizeImageUrls(html, baseUrl, originalImageUrl) {
    const possibleUrls = new Set();
    const baseName = getImageBaseName(originalImageUrl);

    // Create a temporary element to parse HTML
    const parser = new DOMParser();
    const doc = parser.parseFromString(html, 'text/html');

    // Look for image elements
    const images = doc.querySelectorAll('img[src]');
    images.forEach(img => {
      const src = new URL(img.src, baseUrl).href;
      if (isImageUrl(src)) {
        possibleUrls.add(src);
      }
    });

    // Look for links to images
    const links = doc.querySelectorAll('a[href]');
    links.forEach(link => {
      const href = new URL(link.href, baseUrl).href;
      if (isImageUrl(href)) {
        possibleUrls.add(href);
      }
    });

    // Look for meta tags
    const metaTags = doc.querySelectorAll('meta[content]');
    metaTags.forEach(meta => {
      const content = meta.content;
      if (content && isImageUrl(content)) {
        possibleUrls.add(new URL(content, baseUrl).href);
      }
    });

    return [...possibleUrls];
  }

  // Function to select the best image URL from a list of candidates
  function selectBestImageUrl(urls) {
    if (!urls.length) return null;

    // Score each URL based on various factors
    const urlScores = urls.map(url => {
      let score = 0;
      const lowerUrl = url.toLowerCase();

      // Prefer URLs with indicators of high quality
      if (lowerUrl.includes('original')) score += 10;
      if (lowerUrl.includes('full')) score += 8;
      if (lowerUrl.includes('large')) score += 6;
      if (lowerUrl.includes('high')) score += 4;

      // Look for resolution in URL
      const resMatch = url.match(/\d+x\d+/);
      if (resMatch) {
        const [width, height] = resMatch[0].split('x').map(Number);
        score += Math.log(width * height);
      }

      return { url, score };
    });

    // Return URL with highest score
    return urlScores.reduce((best, current) =>
      current.score > best.score ? current : best
    ).url;
  }

  // Function to get storage key prefix
  function getStorageKeyPrefix() {
    return 'imageCollector_';
  }

  // Function to save data to storage
  function saveToStorage(key, data) {
    try {
      // Use GM_setValue if available (Tampermonkey/Greasemonkey)
      if (typeof GM_setValue === 'function') {
        GM_setValue(key, data);
        return;
      }

      // Fallback to localStorage
      localStorage.setItem(key, JSON.stringify(data));
    } catch (e) {
      console.error('Failed to save to storage:', e);
    }
  }

  // Function to save crawler state
  function saveCrawlerState() {
    if (!currentMethod) return;

    // Convert imageHierarchy to serializable format
    const serializableHierarchy = {
      boards: Array.from(imageHierarchy.boards.entries()).map(([boardName, threads]) => {
        return [
          boardName,
          Array.from(threads.entries()).map(([threadId, threadData]) => {
            return [threadId, { ...threadData }];
          })
        ];
      })
    };

    const state = {
      processedUrls: [...processedPageUrls],
      processedImages: [...processedImageUrls],
      pendingLinks: [...pendingLinks],
      foundImages: [...foundImages],
      imageGroups: Array.from(imageGroups.entries()),
      imageHierarchy: serializableHierarchy,
      stats: crawlerStats,
      timestamp: Date.now(),
      userInfo: {
        lastUpdated: "2025-03-13 09:10:37",
        username: "JLSmart13"
      }
    };

    const stateKey = `${getStorageKeyPrefix()}${currentMethod}_state`;
    saveToStorage(stateKey, state);
  }
    // Function to set current collection method
  function setCurrentMethod(method) {
    currentMethod = method;

    // Show crawler controls if in crawler mode
    if (crawlerControls) {
      crawlerControls.style.display = method === 'crawler' ? 'flex' : 'none';
    }

    // Create crawler progress UI if needed
    if (method === 'crawler' && !document.getElementById('crawlerProgress')) {
      createCrawlerProgressUI();
    }
  }

  // Create crawler progress UI
  function createCrawlerProgressUI() {
    // Remove existing progress element if it exists
    const existingProgress = document.getElementById('crawlerProgress');
    if (existingProgress) {
      existingProgress.remove();
    }

    const progress = document.createElement('div');
    progress.id = 'crawlerProgress';
    progress.style.cssText = `
    margin-top: 10px;
    width: 100%;
    background: #444;
    border-radius: 3px;
    overflow: hidden;
    padding: 2px;
    `;

    progress.innerHTML = `
    <div class="progress-bar" style="width: 0%; height: 20px; background: #3498db; transition: width 0.3s; border-radius: 2px;"></div>
    <div class="progress-text" style="text-align: center; margin-top: 5px; font-size: 12px; color: white;">
    Starting crawler...
    </div>
    `;

    if (crawlerControls) {
      crawlerControls.appendChild(progress);
    }
  }

  // Function to pause crawler
  function pauseCrawler() {
    isCrawlerPaused = true;
    pauseResumeButton.textContent = '▶️ Resume';
    statusCounter.textContent += ' (Paused)';
  }

  // Function to resume crawler
  function resumeCrawler() {
    isCrawlerPaused = false;
    pauseResumeButton.textContent = '⏸️ Pause';
    processPendingLinks();
  }

  // Initialize the script
  document.addEventListener('DOMContentLoaded', () => {
    createUI();
    setupEventListeners();
    createFailureLogButton();
  });

  // Alternative initialization for when DOMContentLoaded has already fired
  // Initialize the script based on document readiness
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  // Utility function to load state from storage
  function loadFromStorage(key) {
    try {
      // Use GM_getValue if available (Tampermonkey/Greasemonkey)
      if (typeof GM_getValue === 'function') {
        return GM_getValue(key);
      }

      // Fallback to localStorage
      const data = localStorage.getItem(key);
      return data ? JSON.parse(data) : null;
    } catch (e) {
      console.error('Failed to load from storage:', e);
      return null;
    }
  }

  // Function to load crawler state
  function loadCrawlerState(method) {
    if (!method) return false;

    const stateKey = `${getStorageKeyPrefix()}${method}_state`;
    const savedState = loadFromStorage(stateKey);

    if (!savedState) return false;

    try {
      // Restore processed URLs
      processedPageUrls = new Set(savedState.processedUrls || []);
      
      // Restore processed images
      processedImageUrls = new Set(savedState.processedImages || []);
      
      // Restore pending links
      pendingLinks = savedState.pendingLinks || [];
      
      // Restore found images
      foundImages = savedState.foundImages || [];
      
      // Restore image groups
      imageGroups = new Map();
      if (savedState.imageGroups) {
        savedState.imageGroups.forEach(([key, value]) => {
          imageGroups.set(key, new Set(value));
        });
      }
      
      // Restore image hierarchy
      imageHierarchy = { boards: new Map() };
      if (savedState.imageHierarchy && savedState.imageHierarchy.boards) {
        savedState.imageHierarchy.boards.forEach(([boardName, threads]) => {
          const threadMap = new Map();
          threads.forEach(([threadId, threadData]) => {
            threadMap.set(threadId, threadData);
          });
          imageHierarchy.boards.set(boardName, threadMap);
        });
      }
      
      // Restore crawler stats
      crawlerStats = savedState.stats || {
        startTime: Date.now(),
        lastActive: Date.now(),
        pagesScanned: 0,
        imagesFound: foundImages.length,
        pendingLinksCount: pendingLinks.length,
        domainsCrawled: new Set()
      };
      
      // Update stats with non-serializable Set
      if (savedState.stats && savedState.stats.domainsCrawled) {
        crawlerStats.domainsCrawled = new Set(savedState.stats.domainsCrawled);
      }
      
      // Restore failure log if it exists
      const logKey = `${getStorageKeyPrefix()}${method}_resolutionFailures`;
      const savedFailures = loadFromStorage(logKey);
      if (savedFailures) {
        imageResolutionFailures = savedFailures;
      }

      return true;
    } catch (e) {
      console.error('Error restoring crawler state:', e);
      return false;
    }
  }

  // Function to attempt to load previous state
  function tryLoadPreviousState() {
    // Try to load crawler state first
    if (loadCrawlerState('crawler')) {
      setCurrentMethod('crawler');
      switchModes('crawler');
      updateCounter();
      return true;
    }
    
    // Try to load standard state next
    if (loadCrawlerState('standard')) {
      setCurrentMethod('standard');
      switchModes('standard');
      updateCounter();
      return true;
    }
    
    return false;
  }

  // Function to clear all saved data
  function clearAllSavedData() {
    if (typeof GM_listValues === 'function') {
      const keys = GM_listValues();
      keys.forEach(key => {
        if (key.startsWith(getStorageKeyPrefix())) {
          GM_deleteValue(key);
        }
      });
    } else {
      // Fallback for localStorage
      Object.keys(localStorage).forEach(key => {
        if (key.startsWith(getStorageKeyPrefix())) {
          localStorage.removeItem(key);
        }
      });
    }
    
    // Reset all data structures
    processedPageUrls.clear();
    processedImageUrls.clear();
    pendingLinks = [];
    foundImages = [];
    imageGroups.clear();
    imageHierarchy.boards.clear();
    imageResolutionFailures = [];
    
    // Update UI
    updateCounter();
    
    // Hide failure log button
    if (window.failureLogButton) {
      window.failureLogButton.style.display = 'none';
    }
    
    return true;
  }

  // Update script version information
  const scriptVersion = {
    version: "3.0",
    lastUpdated: "2025-03-13 09:12:40",
    updatedBy: "JLSmart13"
  };

})();
// End of the script