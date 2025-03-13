  // Update counter
  

    // Update status counter
    const counters = [
      `${foundImages.length} media items found`,
      methodText ? `(${methodText})` : '',
      processedPageUrls.size > 1 ? `from ${processedPageUrls.size} pages` : ''
    ].filter(Boolean).join(' ');

    statusCounter.textContent = counters;
  }
  
  // Specialized crawler for anonib.pk
  async function startAnonibCrawler() {
    // Update status
    statusCounter.textContent = "Starting AnonIB crawler...";
    
    // Initialize crawler stats
    crawlerStats.startTime = Date.now();
    crawlerStats.pagesScanned = 0;
    crawlerStats.imagesFound = 0;
    crawlerStats.lastActive = Date.now();
    
    try {
      // Get current URL to determine if we're on a board or catalog page
      const currentPath = window.location.pathname;
      const catalogMatch = currentPath.match(/\/([^\/]+)\/catalog\.html/);
      const boardMatch = currentPath.match(/\/([^\/]+)\/?$/);
      
      if (catalogMatch && catalogMatch[1]) {
        // We're on a catalog page - just process this board
        const boardName = catalogMatch[1];
        
        // Create board entry in hierarchy
        if (!imageHierarchy.boards.has(boardName)) {
          imageHierarchy.boards.set(boardName, new Map());
        }
        
        // Process this board
        await processAnonibBoard(boardName);
      } 
      else if (boardMatch && boardMatch[1] && boardMatch[1].length > 0 && !currentPath.includes('/res/')) {
        // We're on a board index page - just process this board
        const boardName = boardMatch[1];
        
        // Create board entry in hierarchy
        if (!imageHierarchy.boards.has(boardName)) {
          imageHierarchy.boards.set(boardName, new Map());
        }
        
        // Process this board
        await processAnonibBoard(boardName);
      }
      else if (currentPath.includes('/res/')) {
        // We're on a thread page - extract board name and thread id
        const threadMatch = currentPath.match(/\/([^\/]+)\/res\/(\d+)\.html/);
        
        if (threadMatch && threadMatch[1] && threadMatch[2]) {
          const boardName = threadMatch[1];
          const threadId = threadMatch[2];
          
          // Create board entry in hierarchy
          if (!imageHierarchy.boards.has(boardName)) {
            imageHierarchy.boards.set(boardName, new Map());
          }
          
          // Get thread title
          let threadTitle = '';
          const subjectElement = document.querySelector('.innerOP .labelSubject');
          if (subjectElement && subjectElement.textContent.trim()) {
            threadTitle = subjectElement.textContent.trim();
          } else {
            const messageElement = document.querySelector('.innerOP .divMessage');
            if (messageElement && messageElement.textContent.trim()) {
              threadTitle = messageElement.textContent.trim();
              // Truncate long message titles
              if (threadTitle.length > 50) {
                threadTitle = threadTitle.substring(0, 47) + '...';
              }
            }
          }
          
          if (!threadTitle) {
            threadTitle = `Thread #${threadId}`;
          }
          
          // Initialize thread data
          const boardThreads = imageHierarchy.boards.get(boardName);
          boardThreads.set(threadId, {
            title: threadTitle,
            url: window.location.href,
            images: [],
            videos: []
          });
          
          // Process images directly from the DOM on this page
          const imgLinks = document.querySelectorAll('a.imgLink');
          
          imgLinks.forEach(imgLink => {
            const href = imgLink.getAttribute('href');
            if (!href) return;
            
            const fullUrl = new URL(href, window.location.href).href;
            
            // Skip if already processed
            if (processedImageUrls.has(fullUrl)) return;
            
            // Mark as processed
            processedImageUrls.add(fullUrl);
            
            // Determine if it's an image or video
            const mimeType = imgLink.getAttribute('data-filemime') || '';
            const isVideo = mimeType.includes('video') || 
                          fullUrl.match(/\.(mp4|webm|mov|avi|wmv|flv|mkv)$/i);
            
            const threadData = boardThreads.get(threadId);
            
            if (isVideo) {
              if (!threadData.videos.includes(fullUrl)) {
                threadData.videos.push(fullUrl);
                
                // Also add to global list
                if (!foundImages.includes(fullUrl)) {
                  foundImages.push(fullUrl);
                }
              }
            } else {
              if (!threadData.images.includes(fullUrl)) {
                threadData.images.push(fullUrl);
                
                // Also add to global list
                if (!foundImages.includes(fullUrl)) {
                  foundImages.push(fullUrl);
                }
              }
            }
          });
          
          // Update crawler stats
          crawlerStats.pagesScanned = 1;
          crawlerStats.imagesFound = foundImages.length;
        }
      }
      else {
        // We're on the main page - find all boards
        const response = await fetch(window.location.href, { credentials: 'omit' });
        if (!response.ok) throw new Error("Failed to fetch main page");
        
        const html = await response.text();
        const parser = new DOMParser();
        const doc = parser.parseFromString(html, 'text/html');
        
        // Find all board links
        const boardLinks = [];
        const boardElements = doc.querySelectorAll('ul.list-boards a');
        
        boardElements.forEach(link => {
          const href = link.getAttribute('href');
          if (href && href.startsWith('/') && !href.includes('catalog.html')) {
            const boardName = href.split('/')[1];
            if (boardName) {
              boardLinks.push({ url: href, name: boardName });
            }
          }
        });
        
        // Process each board
        for (let i = 0; i < Math.min(5, boardLinks.length); i++) {
          if (!isCrawlerActive) break;
          
          const boardData = boardLinks[i];
          
          // Create board entry in hierarchy if it doesn't exist
          if (!imageHierarchy.boards.has(boardData.name)) {
            imageHierarchy.boards.set(boardData.name, new Map());
          }
          
          // Process this board
          await processAnonibBoard(boardData.name);
          
          // Check if user paused
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
        }
      }
      
      // Crawler finished
      isCrawlerActive = false;
      isProcessing = false;
      
      // Update UI to show hierarchical view
      updateGalleryView('crawler');
      
      // Show completion status
      statusCounter.textContent = `Completed! Scanned ${crawlerStats.pagesScanned} threads, found ${foundImages.length} media items`;
      
    } catch (error) {
      console.error('AnonIB crawler error:', error);
      statusCounter.textContent = `Error: ${error.message}`;
      isCrawlerActive = false;
      isProcessing = false;
    }
  }
  
  // Process a single AnonIB board
  async function processAnonibBoard(boardName) {
    const catalogUrl = `/${boardName}/catalog.html`;
    const fullCatalogUrl = new URL(catalogUrl, window.location.origin).href;
    
    // Update status
    statusCounter.textContent = `Processing board: ${boardName}`;
    
    try {
      // Fetch the catalog
      const catalogResponse = await fetch(fullCatalogUrl, { credentials: 'omit' });
      if (!catalogResponse.ok) return;
      
      const catalogHtml = await catalogResponse.text();
      const catalogDoc = new DOMParser().parseFromString(catalogHtml, 'text/html');
      
      // Find all thread cells
      const threadCells = catalogDoc.querySelectorAll('.catalogCell');
      
      // Process each thread
      for (let j = 0; j < threadCells.length; j++) {
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
        
        const threadCell = threadCells[j];
        const threadLink = threadCell.querySelector('.linkThumb');
        
        if (!threadLink) continue;
        
        const threadHref = threadLink.getAttribute('href');
        if (!threadHref) continue;
        
        // Extract thread ID from href
        let threadId = '';
        const threadIdMatch = threadHref.match(/\/res\/(\d+)\.html/);
        if (threadIdMatch && threadIdMatch[1]) {
          threadId = threadIdMatch[1];
        } else {
          threadId = `unknown_${j}`;
        }
        
        // Get thread URL
        const threadUrl = new URL(threadHref, window.location.origin).href;
        
        // Find the thread title - look for subject or message content
        let threadTitle = '';
        
        // First check for labelSubject
        const subjectElement = threadCell.querySelector('.labelSubject');
        if (subjectElement && subjectElement.textContent.trim()) {
          threadTitle = subjectElement.textContent.trim();
        } 
        
        // If no subject, try the message
        if (!threadTitle) {
          const messageElement = threadCell.querySelector('.divMessage');
          if (messageElement && messageElement.textContent.trim()) {
            threadTitle = messageElement.textContent.trim();
            
            // Truncate long message titles
            if (threadTitle.length > 50) {
              threadTitle = threadTitle.substring(0, 47) + '...';
            }
          }
        }
        
        // If still no title, use generic with ID
        if (!threadTitle) {
          threadTitle = `Thread #${threadId}`;
        }
        
        // Update status
        statusCounter.textContent = `Processing board: ${boardName} - Thread ${j+1}/${threadCells.length} - ${threadTitle}`;
        
        // Get the board's thread map
        const boardThreads = imageHierarchy.boards.get(boardName);
        
        // Initialize thread data
        if (!boardThreads.has(threadId)) {
          boardThreads.set(threadId, {
            title: threadTitle,
            url: threadUrl,
            images: [],
            videos: []
          });
        }
        
        // Update the UI immediately to show progress
        updateGalleryView('crawler');
        
        try {
          // Fetch the thread page
          const threadResponse = await fetch(threadUrl, { credentials: 'omit' });
          if (!threadResponse.ok) continue;
          
          const threadHtml = await threadResponse.text();
          const threadDoc = new DOMParser().parseFromString(threadHtml, 'text/html');
          
          // Get current thread data
          const threadData = boardThreads.get(threadId);
          
          // Find all images in thread using the correct selector
          const imgLinks = threadDoc.querySelectorAll('a.imgLink');
          
          for (const imgLink of imgLinks) {
            const href = imgLink.getAttribute('href');
            if (!href) continue;
            
            const fullUrl = new URL(href, window.location.origin).href;
            
            // Determine if it's an image or video by examining the URL or data-mime attribute
            const mimeType = imgLink.getAttribute('data-filemime') || '';
            const isVideo = mimeType.includes('video') || 
                          fullUrl.match(/\.(mp4|webm|mov|avi|wmv|flv|mkv)$/i);
            
            if (isVideo) {
              // Add to videos list if not already included
              if (!threadData.videos.includes(fullUrl) && !processedImageUrls.has(fullUrl)) {
                threadData.videos.push(fullUrl);
                processedImageUrls.add(fullUrl);
                
                // Also add to global video list if tracking is needed
                if (!foundImages.includes(fullUrl)) {
                  foundImages.push(fullUrl);
                }
              }
            } else {
              // Add to images list if not already included
              if (!threadData.images.includes(fullUrl) && !processedImageUrls.has(fullUrl)) {
                threadData.images.push(fullUrl);
                processedImageUrls.add(fullUrl);
                
                // Also add to global image list
                if (!foundImages.includes(fullUrl)) {
                  foundImages.push(fullUrl);
                }
              }
            }
          }
          
          // Update crawler stats
          crawlerStats.pagesScanned++;
          crawlerStats.imagesFound = foundImages.length;
          crawlerStats.lastActive = Date.now();
          
          // Update UI to show progress
          updateGalleryView('crawler');
          
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
    }
  }

  // Modified collectAnonibImages to handle both images and videos
  function collectAnonibImages(pageUrl, doc) {
    try {
      // Add the page to processed pages
      processedPageUrls.add(pageUrl);
      
      // Look for all imgLink anchors - this is the correct selector for AnonIB images
      const imgLinks = doc.querySelectorAll('a.imgLink');
      
      // If this is a thread page on AnonIB, try to organize by thread
      const currentUrl = new URL(pageUrl);
      const pathParts = currentUrl.pathname.split('/');
      
      // Check if this is a thread page
      const isThreadPage = pathParts.length >= 3 && pathParts[2] === 'res';
      
      // Extract board name and thread ID if applicable
      let boardName = '';
      let threadId = '';
      let threadTitle = '';
      
      if (isThreadPage && pathParts.length >= 4) {
        boardName = pathParts[1];
        // Extract thread ID from URL (e.g., /ak/res/7335.html -> 7335)
        const threadMatch = pathParts[3].match(/(\d+)\.html/);
        if (threadMatch && threadMatch[1]) {
          threadId = threadMatch[1];
        }
        
        // Try to get thread title
        const subjectElement = doc.querySelector('.innerOP .labelSubject');
        if (subjectElement && subjectElement.textContent.trim()) {
          threadTitle = subjectElement.textContent.trim();
        }// Current Date and Time (UTC): 2025-03-13 20:48:03
// Current User's Login: JLSmart13

        const subjectElement = doc.querySelector('.innerOP .labelSubject');
        if (subjectElement && subjectElement.textContent.trim()) {
          threadTitle = subjectElement.textContent.trim();
        } else {
          const messageElement = doc.querySelector('.innerOP .divMessage');
          if (messageElement && messageElement.textContent.trim()) {
            threadTitle = messageElement.textContent.trim();
            // Truncate long message titles
            if (threadTitle.length > 50) {
              threadTitle = threadTitle.substring(0, 47) + '...';
            }
          }
        }
        
        // If no title found, use generic title
        if (!threadTitle) {
          threadTitle = `Thread #${threadId}`;
        }
        
        // Ensure board exists in hierarchy
        if (!imageHierarchy.boards.has(boardName)) {
          imageHierarchy.boards.set(boardName, new Map());
        }
        
        // Get the board's thread map
        const boardThreads = imageHierarchy.boards.get(boardName);
        
        // Initialize thread data if needed
        if (!boardThreads.has(threadId)) {
          boardThreads.set(threadId, {
            title: threadTitle,
            url: pageUrl,
            images: [],
            videos: []
          });
        }
      }
      
      // Process each img link
      imgLinks.forEach(imgLink => {
        const href = imgLink.getAttribute('href');
        if (!href) return;
        
        const fullUrl = new URL(href, pageUrl).href;
        
        // Skip if already processed
        if (processedImageUrls.has(fullUrl)) return;
        
        // Mark as processed
        processedImageUrls.add(fullUrl);
        
        // Determine if it's an image or video by examining the URL or data-mime attribute
        const mimeType = imgLink.getAttribute('data-filemime') || '';
        const isVideo = mimeType.includes('video') || 
                      fullUrl.match(/\.(mp4|webm|mov|avi|wmv|flv|mkv)$/i);
        
        // Add to thread data if applicable
        if (isThreadPage && boardName && threadId) {
          const threadData = imageHierarchy.boards.get(boardName).get(threadId);
          
          if (isVideo) {
            if (!threadData.videos.includes(fullUrl)) {
              threadData.videos.push(fullUrl);
            }
          } else {
            if (!threadData.images.includes(fullUrl)) {
              threadData.images.push(fullUrl);
            }
          }
        }
        
        // Add to global image list
        if (!foundImages.includes(fullUrl)) {
          foundImages.push(fullUrl);
        }
      });
      
      // Look for more thread links to add to pending
      if (currentMethod === 'crawler') {
        const threadLinks = doc.querySelectorAll('.linkThumb');
        
        threadLinks.forEach(link => {
          const href = link.getAttribute('href');
          if (!href) return;
          
          const fullUrl = new URL(href, window.location.origin).href;
          
          // Skip if already processed or pending
          if (processedPageUrls.has(fullUrl) || pendingLinks.includes(fullUrl)) return;
          
          // Add to pending links
          pendingLinks.push(fullUrl);
        });
      }
      
      // Update immediately
      updateGalleryView(currentMethod);
      updateCounter();
    } catch (error) {
      console.error('Error collecting AnonIB images:', error);
    }
  }

  // Update gallery view - enhance to work properly with AnonIB content
  function updateGalleryView(mode) {
    if (!galleryView) return;
    galleryView.innerHTML = '';
    
    // Create container for gallery items
    const container = document.createElement('div');
    container.className = 'gallery-container';
    
    if (mode === 'standard') {
      // Standard mode remains unchanged
      // Display images as a flat gallery
      foundImages.forEach(imgUrl => {
        const imgContainer = createImageContainer(imgUrl, imgUrl);
        container.appendChild(imgContainer);
      });
    } else if (mode === 'crawler' && imageHierarchy && imageHierarchy.boards.size > 0) {
      // Create hierarchical view of boards -> threads -> media
      imageHierarchy.boards.forEach((threads, boardName) => {
        if (threads.size === 0) return; // Skip empty boards
        
        // Create board section
        const boardSection = document.createElement('div');
        boardSection.className = 'board-section';
        
        // Create header for board
        const boardHeader = document.createElement('div');
        boardHeader.className = 'board-header collapsible';
        boardHeader.innerHTML = `<h3>${boardName} <span class="thread-count">(${threads.size} threads)</span></h3>`;
        boardSection.appendChild(boardHeader);
        
        // Create content div for threads
        const boardContent = document.createElement('div');
        boardContent.className = 'board-content';
        
        // Add click event to header for collapsing
        boardHeader.addEventListener('click', () => {
          boardHeader.classList.toggle('collapsed');
          boardContent.style.display = boardContent.style.display === 'none' ? 'block' : 'none';
        });
        
        // Process threads
        threads.forEach((threadData, threadId) => {
          if ((!threadData.images || threadData.images.length === 0) && 
              (!threadData.videos || threadData.videos.length === 0)) return; // Skip threads with no media
          
          // Create thread section
          const threadSection = document.createElement('div');
          threadSection.className = 'thread-section';
          
          // Calculate total media count
          const imageCount = threadData.images ? threadData.images.length : 0;
          const videoCount = threadData.videos ? threadData.videos.length : 0;
          const totalCount = imageCount + videoCount;
          
          // Create header for thread
          const threadHeader = document.createElement('div');
          threadHeader.className = 'thread-header collapsible';
          
          // Create thread info with thread title and media counts
          let mediaCountText = '';
          if (imageCount > 0 && videoCount > 0) {
            mediaCountText = `(${imageCount} images, ${videoCount} videos)`;
          } else if (imageCount > 0) {
            mediaCountText = `(${imageCount} images)`;
          } else if (videoCount > 0) {
            mediaCountText = `(${videoCount} videos)`;
          }
          
          threadHeader.innerHTML = `
            <h4>${threadData.title} <span class="media-count">${mediaCountText}</span></h4>
            <a href="${threadData.url}" target="_blank" class="thread-link" title="Open thread in new tab">🌐</a>
          `;
          
          threadSection.appendChild(threadHeader);
          
          // Create content div for media
          const threadContent = document.createElement('div');
          threadContent.className = 'thread-content';
          
          // Add click event to header for collapsing
          threadHeader.addEventListener('click', (e) => {
            // Don't collapse if clicking the link
            if (e.target.classList.contains('thread-link') || e.target.tagName === 'A') return;
            
            threadHeader.classList.toggle('collapsed');
            threadContent.style.display = threadContent.style.display === 'none' ? 'block' : 'none';
          });
          
          // Create media sections
          if (threadData.images && threadData.images.length > 0) {
            // Images section
            const imagesSection = document.createElement('div');
            imagesSection.className = 'images-section';
            
            // Add images header if there are also videos
            if (threadData.videos && threadData.videos.length > 0) {
              const imagesHeader = document.createElement('h5');
              imagesHeader.textContent = 'Images';
              imagesSection.appendChild(imagesHeader);
            }
            
            // Add images
            threadData.images.forEach(imgUrl => {
              const imgContainer = createImageContainer(imgUrl, imgUrl);
              imagesSection.appendChild(imgContainer);
            });
            
            threadContent.appendChild(imagesSection);
          }
          
          if (threadData.videos && threadData.videos.length > 0) {
            // Videos section
            const videosSection = document.createElement('div');
            videosSection.className = 'videos-section';
            
            // Add videos header if there are also images
            if (threadData.images && threadData.images.length > 0) {
              const videosHeader = document.createElement('h5');
              videosHeader.textContent = 'Videos';
              videosSection.appendChild(videosHeader);
            }
            
            // Add videos
            threadData.videos.forEach(videoUrl => {
              // Create video container similar to image container but with video icon
              const videoContainer = document.createElement('div');
              videoContainer.className = 'image-container video-container';
              videoContainer.title = 'Click to play video';
              
              // Create thumbnail with video icon overlay
              const thumbnail = document.createElement('div');
              thumbnail.className = 'video-thumbnail';
              thumbnail.style.cssText = `
                position: relative;
                width: 150px;
                height: 150px;
                display: flex;
                align-items: center;
                justify-content: center;
                background-color: #222;
                margin: 5px;
                cursor: pointer;
              `;
              
              // Add video icon
              const videoIcon = document.createElement('div');
              videoIcon.innerHTML = '▶️';
              videoIcon.style.cssText = `
                font-size: 48px;
                opacity: 0.8;
              `;
              
              thumbnail.appendChild(videoIcon);
              videoContainer.appendChild(thumbnail);
              
              // Add click event for video
              videoContainer.addEventListener('click', () => {
                window.open(videoUrl, '_blank');
              });
              
              videosSection.appendChild(videoContainer);
            });
            
            threadContent.appendChild(videosSection);
          }
          
          threadSection.appendChild(threadContent);
          boardContent.appendChild(threadSection);
        });
        
        boardSection.appendChild(boardContent);
        container.appendChild(boardSection);
      });
    }
    
    galleryView.appendChild(container);
    
    // Add CSS for collapsible sections
    addCollapseStyles();
  }
  
  // Function to add CSS for collapsible sections
  function addCollapseStyles() {
    // Remove existing style if it exists
    const existingStyle = document.getElementById('collapse-styles');
    if (existingStyle) {
      existingStyle.remove();
    }
    
    const styleElement = document.createElement('style');
    styleElement.id = 'collapse-styles';
    styleElement.textContent = `
      .collapsible {
        cursor: pointer;
        padding: 5px;
        background-color: #333;
        border-radius: 4px;
        margin-bottom: 5px;
        position: relative;
      }
      
      .collapsible:after {
        content: '▼';
        position: absolute;
        right: 10px;
        top: 50%;
        transform: translateY(-50%);
        transition: transform 0.3s;
      }
      
      .collapsible.collapsed:after {
        transform: translateY(-50%) rotate(-90deg);
      }
      
      .board-section {
        margin-bottom: 20px;
      }
      
      .thread-section {
        margin-left: 20px;
        margin-bottom: 10px;
      }
      
      .board-content, .thread-content {
        display: block;
        transition: display 0.3s;
      }
      
      .board-header.collapsed + .board-content,
      .thread-header.collapsed + .thread-content {
        display: none !important;
      }
      
      .thread-link {
        margin-left: 10px;
        text-decoration: none;
        color: lightblue;
      }
      
      .thread-link:hover {
        color: white;
      }
      
      .images-section, .videos-section {
        display: flex;
        flex-wrap: wrap;
        margin-top: 10px;
      }
      
      h5 {
        width: 100%;
        margin: 5px 0;
        font-size: 14px;
        color: #ccc;
      }
      
      .video-container {
        border: 1px solid #555;
      }
    `;
    
    document.head.appendChild(styleElement);
  }
  
  // Create image container - modified to support both images and videos
  function createImageContainer(thumbUrl, fullSizeUrl) {
    const container = document.createElement('div');
    container.className = 'image-container';
    
    // Create thumbnail
    const img = document.createElement('img');
    img.src = thumbUrl;
    img.alt = 'Gallery Image';
    img.style.cssText = `
      max-width: 150px;
      max-height: 150px;
      margin: 5px;
      cursor: pointer;
    `;
    
    // Add click event for lightbox
    img.addEventListener('click', () => {
      showLightbox(fullSizeUrl);
    });
    
    // Add context menu for options
    container.addEventListener('contextmenu', (e) => {
      e.preventDefault();
      showImageInfo(thumbUrl, fullSizeUrl);
    });
    
    container.appendChild(img);
    return container;
  }
  
  // Update crawler progress UI
  function updateCrawlerProgress() {
    const progressElement = document.getElementById('crawlerProgress');
    if (!progressElement) return;
    
    const progressBar = progressElement.querySelector('.progress-bar');
    const progressText = progressElement.querySelector('.progress-text');
    
    if (!progressBar || !progressText) return;
    
    // Calculate progress based on processed URLs vs. total (including pending)
    const totalUrls = processedPageUrls.size + pendingLinks.length;
    const processedUrls = processedPageUrls.size;
    
    let percentComplete = 0;
    if (totalUrls > 0) {
      percentComplete = Math.min(100, Math.round((processedUrls / totalUrls) * 100));
    }
    
    // Update progress bar
    progressBar.style.width = `${percentComplete}%`;
    
    // Update text
    progressText.textContent = `Processed ${processedUrls} pages, found ${foundImages.length} media items (${percentComplete}% complete)`;
    
    // Add time information
    const elapsedTime = (Date.now() - crawlerStats.startTime) / 1000; // in seconds
    const timePerPage = elapsedTime / (processedUrls || 1);
    const remainingPages = pendingLinks.length;
    const estimatedTimeRemaining = remainingPages * timePerPage;
    
    // Format time remaining
    let timeRemainingText = '';
    if (remainingPages > 0) {
      if (estimatedTimeRemaining < 60) {
        timeRemainingText = `${Math.round(estimatedTimeRemaining)} seconds remaining`;
      } else if (estimatedTimeRemaining < 3600) {
        timeRemainingText = `${Math.round(estimatedTimeRemaining / 60)} minutes remaining`;
      } else {
        timeRemainingText = `${Math.round(estimatedTimeRemaining / 3600)} hours remaining`;
      }
      
      progressText.textContent += ` - ${timeRemainingText}`;
    }
  }// Current Date and Time (UTC): 2025-03-13 20:51:22
// Current User's Login: JLSmart13

  // Update crawler progress UI
  function updateCrawlerProgress() {
    const progressElement = document.getElementById('crawlerProgress');
    if (!progressElement) return;
    
    const progressBar = progressElement.querySelector('.progress-bar');
    const progressText = progressElement.querySelector('.progress-text');
    
    if (!progressBar || !progressText) return;
    
    // Calculate progress based on processed URLs vs. total (including pending)
    const totalUrls = processedPageUrls.size + pendingLinks.length;
    const processedUrls = processedPageUrls.size;
    
    let percentComplete = 0;
    if (totalUrls > 0) {
      percentComplete = Math.min(100, Math.round((processedUrls / totalUrls) * 100));
    }
    
    // Update progress bar
    progressBar.style.width = `${percentComplete}%`;
    
    // Update text
    progressText.textContent = `Processed ${processedUrls} pages, found ${foundImages.length} media items (${percentComplete}% complete)`;
    
    // Add time information
    const elapsedTime = (Date.now() - crawlerStats.startTime) / 1000; // in seconds
    const timePerPage = elapsedTime / (processedUrls || 1);
    const remainingPages = pendingLinks.length;
    const estimatedTimeRemaining = remainingPages * timePerPage;
    
    // Format time remaining
    let timeRemainingText = '';
    if (remainingPages > 0) {
      if (estimatedTimeRemaining < 60) {
        timeRemainingText = `${Math.round(estimatedTimeRemaining)} seconds remaining`;
      } else if (estimatedTimeRemaining < 3600) {
        timeRemainingText = `${Math.round(estimatedTimeRemaining / 60)} minutes remaining`;
      } else {
        timeRemainingText = `${Math.round(estimatedTimeRemaining / 3600)} hours remaining`;
      }
      
      progressText.textContent += ` - ${timeRemainingText}`;
    }
  }
  
  // Function to check if an AnonIB URL is supported by the crawler
  function isAnonibUrl(url) {
    const anonibDomain = 'anonib.pk';
    try {
      const urlObj = new URL(url);
      return urlObj.hostname === anonibDomain || urlObj.hostname.endsWith(`.${anonibDomain}`);
    } catch (e) {
      return false;
    }
  }
  
  // Function to determine if an URL is a thread URL
  function isAnonibThreadUrl(url) {
    try {
      const urlObj = new URL(url);
      return urlObj.pathname.includes('/res/') && urlObj.pathname.endsWith('.html');
    } catch (e) {
      return false;
    }
  }
  
  // Function to determine if an URL is a board URL
  function isAnonibBoardUrl(url) {
    try {
      const urlObj = new URL(url);
      const pathParts = urlObj.pathname.split('/');
      // Board URLs are like /ak/ or /ak/index.html
      return pathParts.length >= 2 && pathParts[1].length > 0 && 
          (!pathParts[2] || pathParts[2] === '' || pathParts[2] === 'index.html');
    } catch (e) {
      return false;
    }
  }
  
  // Function to determine if an URL is a catalog URL
  function isAnonibCatalogUrl(url) {
    try {
      const urlObj = new URL(url);
      return urlObj.pathname.includes('catalog.html');
    } catch (e) {
      return false;
    }
  }
  
  // Function to extract board name from URL
  function extractAnonibBoardName(url) {
    try {
      const urlObj = new URL(url);
      const pathParts = urlObj.pathname.split('/');
      if (pathParts.length >= 2 && pathParts[1].length > 0) {
        return pathParts[1];
      }
      return '';
    } catch (e) {
      return '';
    }
  }
  
  // Function to extract thread ID from URL
  function extractAnonibThreadId(url) {
    try {
      const urlObj = new URL(url);
      const match = urlObj.pathname.match(/\/res\/(\d+)\.html/);
      if (match && match[1]) {
        return match[1];
      }
      return '';
    } catch (e) {
      return '';
    }
  }
  
  // Initialize AnonIB crawler UI
  function initializeAnonibCrawlerUI() {
    // Create crawler settings section if it doesn't exist
    let crawlerSettings = document.getElementById('crawlerSettings');
    if (!crawlerSettings) {
      crawlerSettings = document.createElement('div');
      crawlerSettings.id = 'crawlerSettings';
      crawlerSettings.className = 'crawler-settings';
      
      // Add style for crawler settings
      const crawlerSettingsStyle = `
        #crawlerSettings {
          margin-top: 10px;
          padding: 10px;
          background-color: #333;
          border-radius: 5px;
        }
        
        .crawler-option {
          margin-bottom: 10px;
        }
        
        .crawler-option label {
          display: block;
          margin-bottom: 5px;
        }
        
        .crawler-option input[type="checkbox"] {
          margin-right: 5px;
        }
        
        .crawler-option input[type="number"] {
          width: 60px;
          padding: 3px;
          background-color: #222;
          color: #fff;
          border: 1px solid #555;
        }
      `;
      
      const styleElement = document.createElement('style');
      styleElement.textContent = crawlerSettingsStyle;
      document.head.appendChild(styleElement);
      
      // Create AnonIB settings content
      crawlerSettings.innerHTML = `
        <h3>AnonIB Crawler Settings</h3>
        
        <div class="crawler-option">
          <label>
            <input type="checkbox" id="separateMediaTypes" checked>
            Separate images and videos
          </label>
        </div>
        
        <div class="crawler-option">
          <label>
            <input type="checkbox" id="dynamicUpdates" checked>
            Show dynamic updates while crawling
          </label>
        </div>
        
        <div class="crawler-option">
          <label>
            <input type="checkbox" id="collapseThreads">
            Collapse threads by default
          </label>
        </div>
        
        <div class="crawler-option">
          <label for="maxThreadsPerBoard">Max threads per board:</label>
          <input type="number" id="maxThreadsPerBoard" value="50" min="1" max="500">
        </div>
        
        <div class="crawler-option">
          <label for="threadDelay">Delay between thread requests (ms):</label>
          <input type="number" id="threadDelay" value="500" min="100" max="5000" step="100">
        </div>
      `;
      
      // Add settings to the UI
      const controlsContainer = document.getElementById('controlsContainer');
      if (controlsContainer) {
        controlsContainer.appendChild(crawlerSettings);
      }
    }
    
    // Create or update crawler progress section
    let crawlerProgress = document.getElementById('crawlerProgress');
    if (!crawlerProgress) {
      crawlerProgress = document.createElement('div');
      crawlerProgress.id = 'crawlerProgress';
      crawlerProgress.className = 'crawler-progress';
      
      // Add progress bar style
      const progressStyle = `
        .crawler-progress {
          margin-top: 15px;
          padding: 10px;
          background-color: #333;
          border-radius: 5px;
        }
        
        .progress-container {
          height: 20px;
          background-color: #222;
          border-radius: 3px;
          overflow: hidden;
          margin-bottom: 10px;
        }
        
        .progress-bar {
          height: 100%;
          background-color: #4caf50;
          width: 0;
          transition: width 0.3s ease;
        }
        
        .progress-text {
          font-size: 14px;
          color: #ccc;
        }
      `;
      
      const progressStyleElement = document.createElement('style');
      progressStyleElement.textContent = progressStyle;
      document.head.appendChild(progressStyleElement);
      
      // Create progress content
      crawlerProgress.innerHTML = `
        <h3>Crawler Progress</h3>
        <div class="progress-container">
          <div class="progress-bar"></div>
        </div>
        <div class="progress-text">Ready to start crawling</div>
      `;
      
      // Add progress to the UI
      const controlsContainer = document.getElementById('controlsContainer');
      if (controlsContainer) {
        controlsContainer.appendChild(crawlerProgress);
      }
    }
    
    // Update settings based on current state of imageHierarchy
    const separateMediaTypes = document.getElementById('separateMediaTypes');
    if (separateMediaTypes) {
      separateMediaTypes.addEventListener('change', () => {
        // Update gallery view to reflect new setting
        updateGalleryView('crawler');
      });
    }
    
    const collapseThreads = document.getElementById('collapseThreads');
    if (collapseThreads) {
      collapseThreads.addEventListener('change', () => {
        // Toggle collapsed state for all threads
        const threadHeaders = document.querySelectorAll('.thread-header');
        const shouldCollapse = collapseThreads.checked;
        
        threadHeaders.forEach(header => {
          const content = header.nextElementSibling;
          if (shouldCollapse) {
            header.classList.add('collapsed');
            if (content) content.style.display = 'none';
          } else {
            header.classList.remove('collapsed');
            if (content) content.style.display = 'block';
          }
        });
      });
    }
  }
  
  // Initialize AnonIB site handling in the script
  function initializeAnonibSiteHandler() {
    // Check if we're on an AnonIB site
    if (isAnonibUrl(window.location.href)) {
      console.log('AnonIB site detected, initializing specialized handler...');
      
      // Initialize AnonIB UI
      initializeAnonibCrawlerUI();
      
      // Add AnonIB-specific controls
      addAnonibControls();
      
      // If we're on a board or thread page, we can offer direct crawling
      if (isAnonibBoardUrl(window.location.href) || 
          isAnonibCatalogUrl(window.location.href) ||
          isAnonibThreadUrl(window.location.href)) {
        
        // Add a specialized button for the current context
        addCurrentPageCrawlButton();
      }
    }
  }
  
  // Add AnonIB-specific controls to the UI
  function addAnonibControls() {
    const controlsContainer = document.getElementById('controlsContainer');
    if (!controlsContainer) return;
    
    // Create AnonIB controls if they don't exist
    let anonibControls = document.getElementById('anonibControls');
    if (!anonibControls) {
      anonibControls = document.createElement('div');
      anonibControls.id = 'anonibControls';
      anonibControls.className = 'anonib-controls';
      
      // Add styles for the controls
      const controlsStyle = `
        .anonib-controls {
          margin-top: 15px;
          display: flex;
          flex-wrap: wrap;
          gap: 10px;
        }
        
        .anonib-button {
          background-color: #444;
          color: white;
          border: none;
          padding: 8px 15px;
          border-radius: 4px;
          cursor: pointer;
        }
        
        .anonib-button:hover {
          background-color: #555;
        }
        
        .anonib-button.primary {
          background-color: #2967a0;
        }
        
        .anonib-button.primary:hover {
          background-color: #357ab8;
        }
      `;
      
      const controlsStyleElement = document.createElement('style');
      controlsStyleElement.textContent = controlsStyle;
      document.head.appendChild(controlsStyleElement);
      
      controlsContainer.appendChild(anonibControls);
    }
    
    // Clear existing controls
    anonibControls.innerHTML = '';
    
    // Add crawler start button
    const startCrawlerButton = document.createElement('button');
    startCrawlerButton.className = 'anonib-button primary';
    startCrawlerButton.textContent = 'Start AnonIB Crawler';
    startCrawlerButton.addEventListener('click', () => {
      if (!isCrawlerActive) {
        isCrawlerActive = true;
        isProcessing = true;
        currentMethod = 'crawler';
        initializeImageHierarchy();
        startAnonibCrawler();
      } else {
        alert('Crawler is already active!');
      }
    });
    anonibControls.appendChild(startCrawlerButton);
    
    // Add pause/resume button
    const pauseResumeButton = document.createElement('button');
    pauseResumeButton.id = 'pauseResumeButton';
    pauseResumeButton.className = 'anonib-button';
    pauseResumeButton.textContent = 'Pause Crawler';
    pauseResumeButton.addEventListener('click', () => {
      if (isCrawlerActive) {
        isCrawlerPaused = !isCrawlerPaused;
        pauseResumeButton.textContent = isCrawlerPaused ? 'Resume Crawler' : 'Pause Crawler';
        statusCounter.textContent = isCrawlerPaused ? 
          'Crawler paused. Click Resume to continue.' : 
          'Resuming crawler...';
      }
    });
    anonibControls.appendChild(pauseResumeButton);
    
    // Add stop button
    const stopButton = document.createElement('button');
    stopButton.className = 'anonib-button';
    stopButton.textContent = 'Stop Crawler';
    stopButton.addEventListener('click', () => {
      if (isCrawlerActive) {
        isCrawlerActive = false;
        isCrawlerPaused = false;
        isProcessing = false;
        pauseResumeButton.textContent = 'Pause Crawler';
        statusCounter.textContent = 'Crawler stopped.';
      }
    });
    anonibControls.appendChild(stopButton);
    
    // Add clear results button
    const clearButton = document.createElement('button');
    clearButton.className = 'anonib-button';
    clearButton.textContent = 'Clear Results';
    clearButton.addEventListener('click', () => {
      if (!isCrawlerActive || confirm('This will clear all results. Are you sure?')) {
        foundImages = [];
        processedImageUrls.clear();
        processedPageUrls.clear();
        pendingLinks = [];
        initializeImageHierarchy();
        updateGalleryView('crawler');
        updateCounter();
        statusCounter.textContent = 'Results cleared.';
      }
    });
    anonibControls.appendChild(clearButton);
    
    // Add download button
    const// Current Date and Time (UTC): 2025-03-13 20:54:03
// Current User's Login: JLSmart13

    // Add download button
    const downloadButton = document.createElement('button');
    downloadButton.className = 'anonib-button';
    downloadButton.textContent = 'Download URLs';
    downloadButton.addEventListener('click', () => {
      if (foundImages.length === 0) {
        alert('No images found to download');
        return;
      }
      
      // Create organized list of URLs by board and thread
      let content = '// AnonIB Gallery URLs - Generated ' + new Date().toISOString() + '\n\n';
      
      if (imageHierarchy && imageHierarchy.boards.size > 0) {
        imageHierarchy.boards.forEach((threads, boardName) => {
          content += `// Board: ${boardName}\n`;
          
          threads.forEach((threadData, threadId) => {
            content += `// Thread: ${threadData.title} (${threadId})\n`;
            content += `// Thread URL: ${threadData.url}\n\n`;
            
            if (threadData.images && threadData.images.length > 0) {
              content += `// Images (${threadData.images.length}):\n`;
              threadData.images.forEach(imgUrl => {
                content += imgUrl + '\n';
              });
              content += '\n';
            }
            
            if (threadData.videos && threadData.videos.length > 0) {
              content += `// Videos (${threadData.videos.length}):\n`;
              threadData.videos.forEach(videoUrl => {
                content += videoUrl + '\n';
              });
              content += '\n';
            }
            
            content += '// -------------------------------------------\n\n';
          });
          
          content += '// ===========================================\n\n';
        });
      } else {
        // Flat list
        content += '// All URLs:\n';
        foundImages.forEach(url => {
          content += url + '\n';
        });
      }
      
      // Create download link
      const blob = new Blob([content], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'anonib_gallery_urls.txt';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    });
    anonibControls.appendChild(downloadButton);
  }
  
  // Add button to crawl the current page context
  function addCurrentPageCrawlButton() {
    const anonibControls = document.getElementById('anonibControls');
    if (!anonibControls) return;
    
    // Create current page crawl button
    const currentPageButton = document.createElement('button');
    currentPageButton.className = 'anonib-button primary';
    
    // Determine the current context
    if (isAnonibThreadUrl(window.location.href)) {
      currentPageButton.textContent = 'Crawl Current Thread';
      currentPageButton.addEventListener('click', () => {
        if (!isCrawlerActive) {
          isCrawlerActive = true;
          isProcessing = true;
          currentMethod = 'crawler';
          initializeImageHierarchy();
          
          // Extract thread information
          const boardName = extractAnonibBoardName(window.location.href);
          const threadId = extractAnonibThreadId(window.location.href);
          
          // Update status
          statusCounter.textContent = `Collecting images from thread ${threadId} on board ${boardName}...`;
          
          // Process current thread
          if (boardName && threadId) {
            // Create board entry in hierarchy
            if (!imageHierarchy.boards.has(boardName)) {
              imageHierarchy.boards.set(boardName, new Map());
            }
            
            // Get thread title
            let threadTitle = '';
            const subjectElement = document.querySelector('.innerOP .labelSubject');
            if (subjectElement && subjectElement.textContent.trim()) {
              threadTitle = subjectElement.textContent.trim();
            } else {
              const messageElement = document.querySelector('.innerOP .divMessage');
              if (messageElement && messageElement.textContent.trim()) {
                threadTitle = messageElement.textContent.trim();
                // Truncate long message titles
                if (threadTitle.length > 50) {
                  threadTitle = threadTitle.substring(0, 47) + '...';
                }
              }
            }
            
            if (!threadTitle) {
              threadTitle = `Thread #${threadId}`;
            }
            
            // Initialize thread data
            const boardThreads = imageHierarchy.boards.get(boardName);
            boardThreads.set(threadId, {
              title: threadTitle,
              url: window.location.href,
              images: [],
              videos: []
            });
            
            // Process images directly from the DOM
            collectAnonibImages(window.location.href, document);
            
            // Complete processing
            isCrawlerActive = false;
            isProcessing = false;
            statusCounter.textContent = `Completed! Found ${foundImages.length} media items in thread`;
            
            // Update UI
            updateGalleryView('crawler');
          }
        } else {
          alert('Crawler is already active!');
        }
      });
    }
    else if (isAnonibCatalogUrl(window.location.href) || isAnonibBoardUrl(window.location.href)) {
      currentPageButton.textContent = 'Crawl Current Board';
      currentPageButton.addEventListener('click', () => {
        if (!isCrawlerActive) {
          isCrawlerActive = true;
          isProcessing = true;
          currentMethod = 'crawler';
          initializeImageHierarchy();
          
          // Extract board name
          const boardName = extractAnonibBoardName(window.location.href);
          
          if (boardName) {
            // Create board entry in hierarchy
            if (!imageHierarchy.boards.has(boardName)) {
              imageHierarchy.boards.set(boardName, new Map());
            }
            
            // Process this board
            processAnonibBoard(boardName).then(() => {
              // Crawler finished
              isCrawlerActive = false;
              isProcessing = false;
              
              // Update UI
              updateGalleryView('crawler');
              
              // Show completion status
              statusCounter.textContent = `Completed! Found ${foundImages.length} media items on board ${boardName}`;
            }).catch(error => {
              console.error('Error processing board:', error);
              statusCounter.textContent = `Error: ${error.message}`;
              isCrawlerActive = false;
              isProcessing = false;
            });
          }
        } else {
          alert('Crawler is already active!');
        }
      });
    }
    
    // Add the button to controls
    if (currentPageButton.textContent) {
      anonibControls.insertBefore(currentPageButton, anonibControls.firstChild);
    }
  }
  
  // Initialize image hierarchy for organizing media
  function initializeImageHierarchy() {
    imageHierarchy = {
      boards: new Map() // Map of board name -> Map of thread ID -> thread data
    };
  }// Current Date and Time (UTC): 2025-03-13 20:55:30
// Current User's Login: JLSmart13

  // Initialize image hierarchy for organizing media
  function initializeImageHierarchy() {
    imageHierarchy = {
      boards: new Map() // Map of board name -> Map of thread ID -> thread data
    };
  }
  
  // Helper function to safely create a URL
  function safeCreateURL(url, base) {
    try {
      return new URL(url, base);
    } catch (e) {
      console.error('Invalid URL:', url, base);
      return null;
    }
  }
  
  // Helper function to handle fetch errors gracefully
  async function safeFetch(url, options = {}) {
    try {
      const response = await fetch(url, {
        ...options,
        credentials: 'omit',
        timeout: 10000 // 10 second timeout
      });
      return response;
    } catch (error) {
      console.error('Fetch error:', error);
      throw new Error(`Failed to fetch ${url}: ${error.message}`);
    }
  }
  
  // Helper function to extract text from an element safely
  function safeExtractText(element) {
    if (!element) return '';
    return element.textContent.trim();
  }
  
  // Helper function to debounce UI updates for better performance
  function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
      const later = () => {
        clearTimeout(timeout);
        func(...args);
      };
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
    };
  }
  
  // Debounced version of gallery update function to prevent UI freezing
  const debouncedUpdateGallery = debounce((mode) => {
    updateGalleryView(mode);
  }, 500);
  
  // Enhanced function to show lightbox for both images and videos
  function showLightbox(mediaUrl) {
    // Create lightbox if it doesn't exist
    let lightbox = document.getElementById('customLightbox');
    if (!lightbox) {
      lightbox = document.createElement('div');
      lightbox.id = 'customLightbox';
      lightbox.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background-color: rgba(0, 0, 0, 0.9);
        display: flex;
        justify-content: center;
        align-items: center;
        z-index: 1000;
      `;
      
      // Close on click outside the media
      lightbox.addEventListener('click', (e) => {
        if (e.target === lightbox) {
          lightbox.remove();
        }
      });
      
      // Close on ESC key
      document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && document.getElementById('customLightbox')) {
          lightbox.remove();
        }
      });
      
      document.body.appendChild(lightbox);
    } else {
      // Clear existing content
      lightbox.innerHTML = '';
    }
    
    // Determine media type
    const isVideo = mediaUrl.match(/\.(mp4|webm|mov|avi|wmv|flv|mkv)$/i);
    
    if (isVideo) {
      // Create video element
      const video = document.createElement('video');
      video.controls = true;
      video.autoplay = true;
      video.style.cssText = `
        max-width: 90%;
        max-height: 90%;
      `;
      
      const source = document.createElement('source');
      source.src = mediaUrl;
      source.type = `video/${mediaUrl.split('.').pop()}`;
      
      video.appendChild(source);
      lightbox.appendChild(video);
      
      // Add a fallback link for video
      const fallbackLink = document.createElement('a');
      fallbackLink.href = mediaUrl;
      fallbackLink.target = '_blank';
      fallbackLink.textContent = 'Open video in new tab';
      fallbackLink.style.cssText = `
        position: absolute;
        bottom: 20px;
        color: white;
        text-decoration: underline;
      `;
      lightbox.appendChild(fallbackLink);
    } else {
      // Create image element
      const img = document.createElement('img');
      img.src = mediaUrl;
      img.alt = 'Full-size image';
      img.style.cssText = `
        max-width: 90%;
        max-height: 90%;
      `;
      lightbox.appendChild(img);
    }
  }
  
  // Function to show image information and options
  function showImageInfo(thumbUrl, fullSizeUrl) {
    // Create context menu if it doesn't exist
    let contextMenu = document.getElementById('imageContextMenu');
    if (!contextMenu) {
      contextMenu = document.createElement('div');
      contextMenu.id = 'imageContextMenu';
      contextMenu.style.cssText = `
        position: fixed;
        background-color: #333;
        border: 1px solid #555;
        border-radius: 5px;
        padding: 10px;
        z-index: 1001;
        box-shadow: 0 2px 5px rgba(0, 0, 0, 0.5);
      `;
      document.body.appendChild(contextMenu);
      
      // Close when clicking elsewhere
      document.addEventListener('click', (e) => {
        if (!contextMenu.contains(e.target) && document.getElementById('imageContextMenu')) {
          contextMenu.remove();
        }
      });
    }
    
    // Position at the cursor
    contextMenu.style.left = `${mouseX}px`;
    contextMenu.style.top = `${mouseY}px`;
    
    // Determine media type
    const isVideo = fullSizeUrl.match(/\.(mp4|webm|mov|avi|wmv|flv|mkv)$/i);
    const mediaType = isVideo ? 'Video' : 'Image';
    
    // Create content
    contextMenu.innerHTML = `
      <div style="margin-bottom: 10px; font-weight: bold;">${mediaType} Options</div>
      <div style="margin-bottom: 5px; overflow-wrap: break-word; max-width: 300px;">
        URL: <a href="${fullSizeUrl}" target="_blank" style="color: lightblue;">${fullSizeUrl.substring(0, 50)}${fullSizeUrl.length > 50 ? '...' : ''}</a>
      </div>
      <button id="openInNewTab" style="margin-right: 5px; padding: 5px;">Open in new tab</button>
      <button id="copyUrl" style="padding: 5px;">Copy URL</button>
    `;
    
    // Add event listeners for buttons
    document.getElementById('openInNewTab').addEventListener('click', () => {
      window.open(fullSizeUrl, '_blank');
      contextMenu.remove();
    });
    
    document.getElementById('copyUrl').addEventListener('click', () => {
      navigator.clipboard.writeText(fullSizeUrl).then(() => {
        alert('URL copied to clipboard');
        contextMenu.remove();
      }).catch(err => {
        console.error('Failed to copy URL:', err);
        alert('Failed to copy URL');
      });
    });
  }
  
  // Track mouse position for context menu
  let mouseX = 0;
  let mouseY = 0;
  document.addEventListener('mousemove', (e) => {
    mouseX = e.clientX;
    mouseY = e.clientY;
  });// Current Date and Time (UTC): 2025-03-13 20:57:03
// Current User's Login: JLSmart13

  // Track mouse position for context menu
  let mouseX = 0;
  let mouseY = 0;
  document.addEventListener('mousemove', (e) => {
    mouseX = e.clientX;
    mouseY = e.clientY;
  });
  
  // Export data for backup or sharing
  function exportGalleryData() {
    if (foundImages.length === 0 && (!imageHierarchy || imageHierarchy.boards.size === 0)) {
      alert('No gallery data to export');
      return;
    }
    
    // Prepare export data
    const exportData = {
      version: '1.0',
      timestamp: Date.now(),
      foundImages: foundImages,
      processedImageUrls: Array.from(processedImageUrls),
      processedPageUrls: Array.from(processedPageUrls),
      crawlerStats: crawlerStats,
      hierarchy: {
        boards: Array.from(imageHierarchy.boards).map(([boardName, threads]) => {
          return {
            boardName,
            threads: Array.from(threads).map(([threadId, threadData]) => {
              return {
                threadId,
                title: threadData.title,
                url: threadData.url,
                images: threadData.images || [],
                videos: threadData.videos || []
              };
            })
          };
        })
      }
    };
    
    // Convert to JSON and create download link
    const jsonStr = JSON.stringify(exportData, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `anonib_gallery_data_${new Date().toISOString().replace(/:/g, '-')}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }
  
  // Import previously exported data
  function importGalleryData() {
    // Create file input
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    
    input.onchange = (e) => {
      const file = e.target.files[0];
      if (!file) return;
      
      const reader = new FileReader();
      reader.onload = (event) => {
        try {
          const data = JSON.parse(event.target.result);
          
          // Verify it's valid gallery data
          if (!data.version || !data.timestamp || !data.hierarchy) {
            throw new Error('Invalid gallery data format');
          }
          
          // Reset current data
          foundImages = data.foundImages || [];
          processedImageUrls = new Set(data.processedImageUrls || []);
          processedPageUrls = new Set(data.processedPageUrls || []);
          crawlerStats = data.crawlerStats || {
            startTime: Date.now(),
            pagesScanned: 0,
            imagesFound: 0,
            lastActive: Date.now()
          };
          
          // Rebuild hierarchy
          imageHierarchy = { boards: new Map() };
          
          if (data.hierarchy && data.hierarchy.boards) {
            data.hierarchy.boards.forEach(boardData => {
              const boardThreads = new Map();
              
              if (boardData.threads) {
                boardData.threads.forEach(threadData => {
                  boardThreads.set(threadData.threadId, {
                    title: threadData.title || `Thread #${threadData.threadId}`,
                    url: threadData.url || '',
                    images: threadData.images || [],
                    videos: threadData.videos || []
                  });
                });
              }
              
              imageHierarchy.boards.set(boardData.boardName, boardThreads);
            });
          }
          
          // Update UI
          updateGalleryView('crawler');
          updateCounter();
          
          statusCounter.textContent = `Imported gallery data with ${foundImages.length} media items`;
          
        } catch (error) {
          console.error('Error importing data:', error);
          alert(`Error importing data: ${error.message}`);
        }
      };
      
      reader.readAsText(file);
    };
    
    input.click();
  }
  
  // Set up event listeners for the document
  function setupGlobalEventListeners() {
    // Listen for keyboard shortcuts
    document.addEventListener('keydown', (e) => {
      // Ctrl+S to save data
      if (e.ctrlKey && e.key === 's') {
        e.preventDefault();
        exportGalleryData();
      }
      
      // Ctrl+O to open/import data
      if (e.ctrlKey && e.key === 'o') {
        e.preventDefault();
        importGalleryData();
      }
      
      // Escape key to close modals is already handled in showLightbox
    });
    
    // Detect if we're on AnonIB site
    if (isAnonibUrl(window.location.href)) {
      initializeAnonibSiteHandler();
    }
  }
  
  // On script load, check if we need specialized handlers
  (function checkSiteType() {
    // Handle different site types
    if (isAnonibUrl(window.location.href)) {
      console.log('AnonIB site detected, initializing specialized crawler...');
      initializeImageHierarchy();
      setupGlobalEventListeners();
    }
  })();// Current Date and Time (UTC): 2025-03-13 20:59:30
// Current User's Login: JLSmart13

  // On script load, check if we need specialized handlers
  (function checkSiteType() {
    // Handle different site types
    if (isAnonibUrl(window.location.href)) {
      console.log('AnonIB site detected, initializing specialized crawler...');
      initializeImageHierarchy();
      setupGlobalEventListeners();
    }
  })();

  // Add unit tests for the AnonIB crawler functions
  function testAnonibCrawlerFunctions() {
    // This function would be used during development to test the crawler functions
    
    // Test URL parsing
    console.log('Testing URL functions:');
    
    const testUrls = [
      'https://anonib.pk/',
      'https://anonib.pk/ak/',
      'https://anonib.pk/ak/index.html',
      'https://anonib.pk/ak/catalog.html',
      'https://anonib.pk/ak/res/12345.html',
      'https://example.com/not/anonib'
    ];
    
    for (const url of testUrls) {
      console.log(`URL: ${url}`);
      console.log(`  isAnonibUrl: ${isAnonibUrl(url)}`);
      console.log(`  isAnonibThreadUrl: ${isAnonibThreadUrl(url)}`);
      console.log(`  isAnonibBoardUrl: ${isAnonibBoardUrl(url)}`);
      console.log(`  isAnonibCatalogUrl: ${isAnonibCatalogUrl(url)}`);
      console.log(`  boardName: ${extractAnonibBoardName(url)}`);
      console.log(`  threadId: ${extractAnonibThreadId(url)}`);
      console.log('---');
    }
    
    // Test HTML parsing with sample HTML
    const testThreadHTML = `
      <div class="innerOP">
        <span class="labelSubject">Test Thread Title</span>
        <div class="divMessage">This is the message content</div>
        <a class="imgLink" href="/file/12345.jpg">Image Link</a>
        <a class="imgLink" href="/file/67890.mp4" data-filemime="video/mp4">Video Link</a>
      </div>
    `;
    
    const testCatalogHTML = `
      <div class="catalogCell">
        <a class="linkThumb" href="/ak/res/12345.html">Thread Link</a>
        <span class="labelSubject">Thread with subject</span>
        <div class="divMessage">Thread message</div>
      </div>
      <div class="catalogCell">
        <a class="linkThumb" href="/ak/res/67890.html">Thread Link</a>
        <span class="labelSubject"></span>
        <div class="divMessage">Thread with no subject</div>
      </div>
    `;
    
    console.log('Testing HTML parsing:');
    
    // Parse test HTML
    const threadParser = new DOMParser();
    const threadDoc = threadParser.parseFromString(testThreadHTML, 'text/html');
    
    const catalogParser = new DOMParser();
    const catalogDoc = catalogParser.parseFromString(testCatalogHTML, 'text/html');
    
    // Test thread parsing
    console.log('Thread parsing:');
    const subjectElement = threadDoc.querySelector('.innerOP .labelSubject');
    const messageElement = threadDoc.querySelector('.innerOP .divMessage');
    const imgLinks = threadDoc.querySelectorAll('a.imgLink');
    
    console.log(`  Subject: ${safeExtractText(subjectElement)}`);
    console.log(`  Message: ${safeExtractText(messageElement)}`);
    console.log(`  Image links found: ${imgLinks.length}`);
    
    imgLinks.forEach((link, i) => {
      const href = link.getAttribute('href');
      const mimeType = link.getAttribute('data-filemime') || '';
      const isVideo = mimeType.includes('video') || href.match(/\.(mp4|webm|mov|avi|wmv|flv|mkv)$/i);
      
      console.log(`  Link ${i+1}: ${href} (${isVideo ? 'Video' : 'Image'})`);
    });
    
    // Test catalog parsing
    console.log('Catalog parsing:');
    const threadCells = catalogDoc.querySelectorAll('.catalogCell');
    
    console.log(`  Thread cells found: ${threadCells.length}`);
    
    threadCells.forEach((cell, i) => {
      const threadLink = cell.querySelector('.linkThumb');
      const threadHref = threadLink ? threadLink.getAttribute('href') : '';
      
      const subjectText = safeExtractText(cell.querySelector('.labelSubject'));
      const messageText = safeExtractText(cell.querySelector('.divMessage'));
      
      let threadTitle = '';
      if (subjectText) {
        threadTitle = subjectText;
      } else if (messageText) {
        threadTitle = messageText.length > 50 ? messageText.substring(0, 47) + '...' : messageText;
      }
      
      console.log(`  Thread ${i+1}: ${threadHref}`);
      console.log(`    Title: ${threadTitle}`);
    });
  }
  
  // Helper function to parse a thread info from a catalog cell
  function parseThreadInfoFromCatalogCell(cell) {
    if (!cell) return null;
    
    const threadLink = cell.querySelector('.linkThumb');
    if (!threadLink) return null;
    
    const threadHref = threadLink.getAttribute('href');
    if (!threadHref) return null;
    
    // Extract thread ID from href
    let threadId = '';
    const threadIdMatch = threadHref.match(/\/res\/(\d+)\.html/);
    if (threadIdMatch && threadIdMatch[1]) {
      threadId = threadIdMatch[1];
    } else {
      return null;
    }
    
    // Find the thread title
    let threadTitle = '';
    
    // First check for labelSubject
    const subjectElement = cell.querySelector('.labelSubject');
    if (subjectElement && subjectElement.textContent.trim()) {
      threadTitle = subjectElement.textContent.trim();
    }
    
    // If no subject, try the message
    if (!threadTitle) {
      const messageElement = cell.querySelector('.divMessage');
      if (messageElement && messageElement.textContent.trim()) {
        threadTitle = messageElement.textContent.trim();
        
        // Truncate long message titles
        if (threadTitle.length > 50) {
          threadTitle = threadTitle.substring(0, 47) + '...';
        }
      }
    }
    
    // If still no title, use generic with ID
    if (!threadTitle) {
      threadTitle = `Thread #${threadId}`;
    }
    
    // Get the full URL
    const fullUrl = new URL(threadHref, window.location.origin).href;
    
    return {
      id: threadId,
      title: threadTitle,
      url: fullUrl
    };
  }
  
  // Final cleanup and integration
  console.log('AnonIB crawler module loaded and ready.');// Current Date and Time (UTC): 2025-03-13 21:01:12
// Current User's Login: JLSmart13

  // Final cleanup and integration
  console.log('AnonIB crawler module loaded and ready.');

  // Initialize global variables and data structures if not already set
  if (typeof foundImages === 'undefined') {
    var foundImages = [];
  }
  
  if (typeof processedImageUrls === 'undefined') {
    var processedImageUrls = new Set();
  }
  
  if (typeof processedPageUrls === 'undefined') {
    var processedPageUrls = new Set();
  }
  
  if (typeof pendingLinks === 'undefined') {
    var pendingLinks = [];
  }
  
  if (typeof imageHierarchy === 'undefined') {
    var imageHierarchy = {
      boards: new Map()
    };
  }
  
  if (typeof isCrawlerActive === 'undefined') {
    var isCrawlerActive = false;
  }
  
  if (typeof isCrawlerPaused === 'undefined') {
    var isCrawlerPaused = false;
  }
  
  if (typeof isProcessing === 'undefined') {
    var isProcessing = false;
  }
  
  if (typeof currentMethod === 'undefined') {
    var currentMethod = 'standard';
  }
  
  if (typeof crawlerStats === 'undefined') {
    var crawlerStats = {
      startTime: 0,
      pagesScanned: 0,
      imagesFound: 0,
      lastActive: 0
    };
  }
  
  // Get UI elements
  const galleryView = document.getElementById('galleryView');
  const statusCounter = document.getElementById('statusCounter');
  
  // Additional helpers for AnonIB-specific processing
  
  // Function to parse image URLs from different contexts
  function parseImageUrlsFromPage(doc) {
    // Find all image links
    const imgLinks = doc.querySelectorAll('a.imgLink');
    const results = {
      images: [],
      videos: []
    };
    
    imgLinks.forEach(imgLink => {
      const href = imgLink.getAttribute('href');
      if (!href) return;
      
      const fullUrl = new URL(href, window.location.href).href;
      
      // Skip if already processed
      if (processedImageUrls.has(fullUrl)) return;
      
      // Mark as processed
      processedImageUrls.add(fullUrl);
      
      // Determine if it's an image or video by examining the URL or data-mime attribute
      const mimeType = imgLink.getAttribute('data-filemime') || '';
      const isVideo = mimeType.includes('video') || 
                    fullUrl.match(/\.(mp4|webm|mov|avi|wmv|flv|mkv)$/i);
      
      if (isVideo) {
        results.videos.push(fullUrl);
      } else {
        results.images.push(fullUrl);
      }
    });
    
    return results;
  }
  
  // Function to safely add an image/video to a thread
  function addMediaToThread(boardName, threadId, mediaUrl, isVideo) {
    // Ensure board exists
    if (!imageHierarchy.boards.has(boardName)) {
      imageHierarchy.boards.set(boardName, new Map());
    }
    
    const boardThreads = imageHierarchy.boards.get(boardName);
    
    // Ensure thread exists
    if (!boardThreads.has(threadId)) {
      boardThreads.set(threadId, {
        title: `Thread #${threadId}`,
        url: `${window.location.origin}/${boardName}/res/${threadId}.html`,
        images: [],
        videos: []
      });
    }
    
    const threadData = boardThreads.get(threadId);
    
    // Add media to appropriate array if not already there
    if (isVideo) {
      if (!threadData.videos.includes(mediaUrl)) {
        threadData.videos.push(mediaUrl);
      }
    } else {
      if (!threadData.images.includes(mediaUrl)) {
        threadData.images.push(mediaUrl);
      }
    }
  }
  
  // Function to help with error recovery during crawling
  function recoverFromCrawlerError(error) {
    console.error('Crawler error:', error);
    statusCounter.textContent = `Error: ${error.message} - attempting to continue...`;
    
    // If we have pending links, try to continue with the next one
    if (pendingLinks.length > 0 && isCrawlerActive) {
      const nextUrl = pendingLinks.shift();
      
      // Try to continue with a delay
      setTimeout(async () => {
        try {
          const response = await fetch(nextUrl, { credentials: 'omit' });
          if (response.ok) {
            const html = await response.text();
            const parser = new DOMParser();
            const doc = parser.parseFromString(html, 'text/html');
            
            // Process the page
            collectAnonibImages(nextUrl, doc);
            
            // Update counters
            crawlerStats.pagesScanned++;
            crawlerStats.lastActive = Date.now();
            
            // Continue crawler loop
            processCrawlerQueue();
          }
        } catch (recoveryError) {
          console.error('Failed to recover crawler:', recoveryError);
        }
      }, 2000); // Wait 2 seconds before trying to continue
    } else {
      // We can't recover, stop the crawler
      isCrawlerActive = false;
      isProcessing = false;
      statusCounter.textContent = `Crawler stopped due to error: ${error.message}`;
    }
  }
  
  // Function to process the crawler queue
  async function processCrawlerQueue() {
    if (!isCrawlerActive || isCrawlerPaused) {
      return;
    }
    
    if (pendingLinks.length === 0) {
      // Crawler queue is empty, complete crawling
      isCrawlerActive = false;
      isProcessing = false;
      statusCounter.textContent = `Completed! Scanned ${crawlerStats.pagesScanned} pages, found ${foundImages.length} media items`;
      return;
    }
    
    try {
      // Get the next URL
      const nextUrl = pendingLinks.shift();
      
      // Skip if already processed
      if (processedPageUrls.has(nextUrl)) {
        processCrawlerQueue();
        return;
      }
      
      // Update status
      statusCounter.textContent = `Processing: ${nextUrl}`;
      
      // Fetch the page
      const response = await fetch(nextUrl, { credentials: 'omit' });
      if (!response.ok) {
        console.warn(`Failed to fetch ${nextUrl}: ${response.status} ${response.statusText}`);
        processCrawlerQueue();
        return;
      }
      
      const html = await response.text();
      const parser = new DOMParser();
      const doc = parser.parseFromString(html, 'text/html');
      
      // Process the page
      collectAnonibImages(nextUrl, doc);
      
      // Update counters
      crawlerStats.pagesScanned++;
      crawlerStats.lastActive = Date.now();
      
      // Add a small delay to prevent overwhelming the server
      setTimeout(processCrawlerQueue, 500);
      
    } catch (error) {
      recoverFromCrawlerError(error);
    }
  }
  
  // Additional UI enhancements for the AnonIB crawler
  
  // Function to add drag-and-drop functionality for reordering threads
  function enableDragAndDrop() {
    const threadSections = document.querySelectorAll('.thread-section');
    
    threadSections.forEach(section => {
      section.setAttribute('draggable', 'true');
      
      section.addEventListener('dragstart', (e) => {
        e.dataTransfer.setData('text/plain', section.dataset.threadId);
        section.classList.add('dragging');
      });
      
      section.addEventListener('dragend', () => {
        section.classList.remove('dragging');
      });
      
      section.addEventListener('dragover', (e) => {
        e.preventDefault();
        section.classList.add('dragover');
      });
      
      section.addEventListener('dragleave', () => {
        section.classList.remove('dragover');
      });
      
      section.addEventListener('drop', (e) => {
        e.preventDefault();
        section.classList.remove('dragover');
        
        const sourceThreadId = e.dataTransfer.getData('text/plain');
        const targetThreadId = section.dataset.threadId;
        
        if (sourceThreadId && targetThreadId && sourceThreadId !== targetThreadId) {
          // Reorder logic would be implemented here
          console.log(`Reorder: ${sourceThreadId} to position of ${targetThreadId}`);
        }
      });
    });
  }
}// Current Date and Time (UTC): 2025-03-13 21:02:34
// Current User's Login: JLSmart13

  // Function to add drag-and-drop functionality for reordering threads
  function enableDragAndDrop() {
    const threadSections = document.querySelectorAll('.thread-section');
    
    threadSections.forEach(section => {
      section.setAttribute('draggable', 'true');
      
      section.addEventListener('dragstart', (e) => {
        e.dataTransfer.setData('text/plain', section.dataset.threadId);
        section.classList.add('dragging');
      });
      
      section.addEventListener('dragend', () => {
        section.classList.remove('dragging');
      });
      
      section.addEventListener('dragover', (e) => {
        e.preventDefault();
        section.classList.add('dragover');
      });
      
      section.addEventListener('dragleave', () => {
        section.classList.remove('dragover');
      });
      
      section.addEventListener('drop', (e) => {
        e.preventDefault();
        section.classList.remove('dragover');
        
        const sourceThreadId = e.dataTransfer.getData('text/plain');
        const targetThreadId = section.dataset.threadId;
        
        if (sourceThreadId && targetThreadId && sourceThreadId !== targetThreadId) {
          // Reorder logic would be implemented here
          console.log(`Reorder: ${sourceThreadId} to position of ${targetThreadId}`);
        }
      });
    });
  }
  
  // Function to add filtering capabilities to the gallery view
  function addFilteringCapabilities() {
    // Create filter controls if they don't exist
    let filterControls = document.getElementById('galleryFilters');
    if (!filterControls) {
      filterControls = document.createElement('div');
      filterControls.id = 'galleryFilters';
      filterControls.className = 'gallery-filters';
      
      // Add style for filters
      const filterStyle = `
        .gallery-filters {
          margin: 10px 0;
          padding: 10px;
          background-color: #333;
          border-radius: 5px;
        }
        
        .filter-row {
          display: flex;
          margin-bottom: 5px;
          align-items: center;
        }
        
        .filter-label {
          margin-right: 10px;
          width: 80px;
        }
        
        .filter-input {
          flex: 1;
          padding: 5px;
          background-color: #222;
          color: white;
          border: 1px solid #555;
          border-radius: 3px;
        }
        
        .filter-buttons {
          margin-top: 10px;
          display: flex;
          justify-content: flex-end;
        }
        
        .filter-button {
          padding: 5px 10px;
          margin-left: 10px;
          background-color: #444;
          color: white;
          border: none;
          border-radius: 3px;
          cursor: pointer;
        }
        
        .filter-button:hover {
          background-color: #555;
        }
        
        .filter-button.primary {
          background-color: #2967a0;
        }
        
        .filter-button.primary:hover {
          background-color: #357ab8;
        }
        
        .media-type-filter {
          display: flex;
          gap: 10px;
        }
        
        .media-type-filter label {
          display: flex;
          align-items: center;
          cursor: pointer;
        }
        
        .media-type-filter input {
          margin-right: 5px;
        }
      `;
      
      const filterStyleElement = document.createElement('style');
      filterStyleElement.textContent = filterStyle;
      document.head.appendChild(filterStyleElement);
      
      // Create filter content
      filterControls.innerHTML = `
        <h3>Filter Gallery</h3>
        
        <div class="filter-row">
          <div class="filter-label">Board:</div>
          <select id="boardFilter" class="filter-input">
            <option value="">All Boards</option>
          </select>
        </div>
        
        <div class="filter-row">
          <div class="filter-label">Thread:</div>
          <input type="text" id="threadFilter" class="filter-input" placeholder="Search thread titles...">
        </div>
        
        <div class="filter-row">
          <div class="filter-label">Media Type:</div>
          <div class="media-type-filter">
            <label>
              <input type="checkbox" id="showImages" checked> 
              Images
            </label>
            <label>
              <input type="checkbox" id="showVideos" checked> 
              Videos
            </label>
          </div>
        </div>
        
        <div class="filter-buttons">
          <button id="applyFilters" class="filter-button primary">Apply Filters</button>
          <button id="resetFilters" class="filter-button">Reset Filters</button>
        </div>
      `;
      
      // Add filters to the UI
      const controlsContainer = document.getElementById('controlsContainer');
      if (controlsContainer) {
        controlsContainer.appendChild(filterControls);
      }
      
      // Populate board filter
      const boardFilter = document.getElementById('boardFilter');
      if (boardFilter && imageHierarchy && imageHierarchy.boards.size > 0) {
        imageHierarchy.boards.forEach((_, boardName) => {
          const option = document.createElement('option');
          option.value = boardName;
          option.textContent = boardName;
          boardFilter.appendChild(option);
        });
      }
      
      // Add event listeners for filter buttons
      const applyFiltersButton = document.getElementById('applyFilters');
      if (applyFiltersButton) {
        applyFiltersButton.addEventListener('click', () => {
          applyGalleryFilters();
        });
      }
      
      const resetFiltersButton = document.getElementById('resetFilters');
      if (resetFiltersButton) {
        resetFiltersButton.addEventListener('click', () => {
          resetGalleryFilters();
        });
      }
    }
  }
  
  // Function to apply filters to gallery view
  function applyGalleryFilters() {
    const boardFilter = document.getElementById('boardFilter');
    const threadFilter = document.getElementById('threadFilter');
    const showImages = document.getElementById('showImages');
    const showVideos = document.getElementById('showVideos');
    
    if (!boardFilter || !threadFilter || !showImages || !showVideos) return;
    
    const selectedBoard = boardFilter.value;
    const threadSearch = threadFilter.value.toLowerCase();
    const displayImages = showImages.checked;
    const displayVideos = showVideos.checked;
    
    // Apply filters
    const boardSections = document.querySelectorAll('.board-section');
    boardSections.forEach(boardSection => {
      const boardHeader = boardSection.querySelector('.board-header');
      const boardName = boardHeader ? boardHeader.textContent.split(' ')[0] : '';
      
      let showBoard = true;
      
      // Filter by board name
      if (selectedBoard && boardName !== selectedBoard) {
        showBoard = false;
      }
      
      // Apply thread filters within boards
      const threadSections = boardSection.querySelectorAll('.thread-section');
      let visibleThreads = 0;
      
      threadSections.forEach(threadSection => {
        const threadHeader = threadSection.querySelector('.thread-header');
        const threadTitle = threadHeader ? threadHeader.textContent.toLowerCase() : '';
        
        let showThread = true;
        
        // Filter by thread title
        if (threadSearch && !threadTitle.includes(threadSearch)) {
          showThread = false;
        }
        
        // Filter by media type
        const hasImages = threadSection.querySelector('.images-section');
        const hasVideos = threadSection.querySelector('.videos-section');
        
        if ((!displayImages && hasImages && !hasVideos) || 
            (!displayVideos && hasVideos && !hasImages) ||
            (!displayImages && !displayVideos)) {
          showThread = false;
        }
        
        // Show/hide thread
        threadSection.style.display = showThread ? 'block' : 'none';
        
        if (showThread) visibleThreads++;
      });
      
      // Show board only if it has visible threads
      boardSection.style.display = (showBoard && visibleThreads > 0) ? 'block' : 'none';
    });
  }
  
  // Function to reset gallery filters
  function resetGalleryFilters() {
    const boardFilter = document.getElementById('boardFilter');
    const threadFilter = document.getElementById('threadFilter');
    const showImages = document.getElementById('showImages');
    const showVideos = document.getElementById('showVideos');
    
    if (boardFilter) boardFilter.value = '';
    if (threadFilter) threadFilter.value = '';
    if (showImages) showImages.checked = true;
    if (showVideos) showVideos.checked = true;
    
    // Show all boards and threads
    const boardSections = document.querySelectorAll('.board-section');
    boardSections.forEach(boardSection => {
      boardSection.style.display = 'block';
      
      const threadSections = boardSection.querySelectorAll('.thread-section');
      threadSections.forEach(threadSection => {
        threadSection.style.display = 'block';
      });
    });
  }
  
  // Function to update UI with statistics
  function updateStatistics() {
    if (!statusCounter) return;
    
    // Count total boards, threads, images, and videos
    let totalBoards = 0;
    let totalThreads = 0;
    let totalImages = 0;
    let totalVideos = 0;
    
    if (imageHierarchy && imageHierarchy.boards) {
      totalBoards = imageHierarchy.boards.size;
      
      imageHierarchy.boards.forEach((threads) => {
        totalThreads += threads.size;
        
        threads.forEach((threadData) => {
          totalImages += threadData.images ? threadData.images.length : 0;
          totalVideos += threadData.videos ? threadData.videos.length : 0;
        });
      });
    }
    
    // Update status counter with statistics
    statusCounter.textContent = `Stats: ${totalBoards} boards, ${totalThreads} threads, ${totalImages} images, ${totalVideos} videos`;
  }
  
  // Help function to provide usage instructions
  function showHelp() {
    alert(`AnonIB Crawler Help:
    
1. Basic Usage:
   - Click "Start AnonIB Crawler" to begin crawling the current site
   - Use "Pause"/"Resume" to control the crawler
   - "Stop Crawler" will end the current crawling session
   - "Clear Results" removes all collected data

2. Controls:
   - Board sections and thread sections can be collapsed by clicking on their headers
   - Right-click on images/videos for additional options
   - Use filters to narrow down results by board, thread title, or media type

3. Keyboard Shortcuts:
   - Ctrl+S: Save/export gallery data
   - Ctrl+O: Open/import gallery data
   - ESC: Close any open lightbox or dialog

4. Tips:
   - The crawler is most efficient when started from a board catalog page
   - You can crawl just the current thread by using the "Crawl Current Thread" button
   - Exported data can be shared and imported on another browser

For more information, check the documentation.`);
  }
}// Current Date and Time (UTC): 2025-03-13 21:04:10
// Current User's Login: JLSmart13

  // Help function to provide usage instructions
  function showHelp() {
    alert(`AnonIB Crawler Help:
    
1. Basic Usage:
   - Click "Start AnonIB Crawler" to begin crawling the current site
   - Use "Pause"/"Resume" to control the crawler
   - "Stop Crawler" will end the current crawling session
   - "Clear Results" removes all collected data

2. Controls:
   - Board sections and thread sections can be collapsed by clicking on their headers
   - Right-click on images/videos for additional options
   - Use filters to narrow down results by board, thread title, or media type

3. Keyboard Shortcuts:
   - Ctrl+S: Save/export gallery data
   - Ctrl+O: Open/import gallery data
   - ESC: Close any open lightbox or dialog

4. Tips:
   - The crawler is most efficient when started from a board catalog page
   - You can crawl just the current thread by using the "Crawl Current Thread" button
   - Exported data can be shared and imported on another browser

For more information, check the documentation.`);
  }
  
  // Function to generate download links for batch downloading
  function generateDownloadLinks() {
    // Create downloadable links if there are images found
    if (foundImages.length === 0) {
      alert('No images found to generate download links');
      return;
    }
    
    // Create modal for download links
    const downloadModal = document.createElement('div');
    downloadModal.id = 'downloadLinksModal';
    downloadModal.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background-color: rgba(0, 0, 0, 0.8);
      display: flex;
      justify-content: center;
      align-items: center;
      z-index: 1001;
    `;
    
    // Create modal content
    const modalContent = document.createElement('div');
    modalContent.style.cssText = `
      width: 80%;
      max-width: 800px;
      max-height: 80%;
      background-color: #333;
      border-radius: 5px;
      padding: 20px;
      overflow-y: auto;
      position: relative;
    `;
    
    // Close button
    const closeButton = document.createElement('button');
    closeButton.textContent = '×';
    closeButton.style.cssText = `
      position: absolute;
      top: 10px;
      right: 10px;
      background: none;
      border: none;
      color: white;
      font-size: 24px;
      cursor: pointer;
    `;
    closeButton.addEventListener('click', () => {
      downloadModal.remove();
    });
    modalContent.appendChild(closeButton);
    
    // Title
    const title = document.createElement('h3');
    title.textContent = 'Download Links';
    title.style.cssText = `
      margin-top: 0;
      margin-bottom: 20px;
    `;
    modalContent.appendChild(title);
    
    // Create tabs for different download formats
    const tabsContainer = document.createElement('div');
    tabsContainer.style.cssText = `
      display: flex;
      margin-bottom: 15px;
      border-bottom: 1px solid #555;
    `;
    
    const tabs = [
      { id: 'plainTextTab', text: 'Plain Text' },
      { id: 'htmlListTab', text: 'HTML List' },
      { id: 'scriptTab', text: 'Download Script' }
    ];
    
    tabs.forEach((tab, index) => {
      const tabButton = document.createElement('button');
      tabButton.id = tab.id;
      tabButton.textContent = tab.text;
      tabButton.style.cssText = `
        padding: 8px 15px;
        background-color: ${index === 0 ? '#444' : '#333'};
        color: white;
        border: none;
        border-bottom: 2px solid ${index === 0 ? '#4caf50' : 'transparent'};
        cursor: pointer;
        margin-right: 5px;
      `;
      
      tabButton.addEventListener('click', () => {
        // Update active tab
        document.querySelectorAll('[id$="Tab"]').forEach(t => {
          t.style.backgroundColor = '#333';
          t.style.borderBottomColor = 'transparent';
        });
        tabButton.style.backgroundColor = '#444';
        tabButton.style.borderBottomColor = '#4caf50';
        
        // Show content for active tab
        document.querySelectorAll('[id$="Content"]').forEach(c => {
          c.style.display = 'none';
        });
        document.getElementById(tab.id.replace('Tab', 'Content')).style.display = 'block';
      });
      
      tabsContainer.appendChild(tabButton);
    });
    
    modalContent.appendChild(tabsContainer);
    
    // Create content containers for each tab
    const plainTextContent = document.createElement('div');
    plainTextContent.id = 'plainTextContent';
    plainTextContent.style.display = 'block';
    
    const htmlListContent = document.createElement('div');
    htmlListContent.id = 'htmlListContent';
    htmlListContent.style.display = 'none';
    
    const scriptContent = document.createElement('div');
    scriptContent.id = 'scriptContent';
    scriptContent.style.display = 'none';
    
    // Create plain text links
    const plainTextArea = document.createElement('textarea');
    plainTextArea.style.cssText = `
      width: 100%;
      height: 300px;
      background-color: #222;
      color: #ddd;
      border: 1px solid #555;
      padding: 10px;
      font-family: monospace;
      resize: vertical;
    `;
    
    // Generate the content based on hierarchy
    let plainTextContent = '';
    
    if (imageHierarchy && imageHierarchy.boards.size > 0) {
      imageHierarchy.boards.forEach((threads, boardName) => {
        plainTextContent += `# Board: ${boardName}\n\n`;
        
        threads.forEach((threadData, threadId) => {
          plainTextContent += `## ${threadData.title}\n`;
          plainTextContent += `## Thread URL: ${threadData.url}\n\n`;
          
          if (threadData.images && threadData.images.length > 0) {
            plainTextContent += `### Images (${threadData.images.length}):\n`;
            threadData.images.forEach(imgUrl => {
              plainTextContent += `${imgUrl}\n`;
            });
            plainTextContent += '\n';
          }
          
          if (threadData.videos && threadData.videos.length > 0) {
            plainTextContent += `### Videos (${threadData.videos.length}):\n`;
            threadData.videos.forEach(videoUrl => {
              plainTextContent += `${videoUrl}\n`;
            });
            plainTextContent += '\n';
          }
          
          plainTextContent += '---\n\n';
        });
        
        plainTextContent += '==========\n\n';
      });
    } else {
      foundImages.forEach(url => {
        plainTextContent += url + '\n';
      });
    }
    
    plainTextArea.value = plainTextContent;
    
    const copyPlainTextButton = document.createElement('button');
    copyPlainTextButton.textContent = 'Copy to Clipboard';
    copyPlainTextButton.style.cssText = `
      margin-top: 10px;
      padding: 8px 15px;
      background-color: #2967a0;
      color: white;
      border: none;
      border-radius: 3px;
      cursor: pointer;
    `;
    copyPlainTextButton.addEventListener('click', () => {
      plainTextArea.select();
      navigator.clipboard.writeText(plainTextArea.value).then(() => {
        copyPlainTextButton.textContent = 'Copied!';
        setTimeout(() => {
          copyPlainTextButton.textContent = 'Copy to Clipboard';
        }, 2000);
      });
    });
    
    plainTextContent.appendChild(plainTextArea);
    plainTextContent.appendChild(copyPlainTextButton);
    
    // Create HTML list content
    const htmlListArea = document.createElement('textarea');
    htmlListArea.style.cssText = `
      width: 100%;
      height: 300px;
      background-color: #222;
      color: #ddd;
      border: 1px solid #555;
      padding: 10px;
      font-family: monospace;
      resize: vertical;
    `;
    
    let htmlListText = '<!DOCTYPE html>\n<html>\n<head>\n  <title>AnonIB Media Links</title>\n  <style>\n';
    htmlListText += '    body { font-family: Arial, sans-serif; background-color: #222; color: #ddd; padding: 20px; }\n';
    htmlListText += '    h1, h2, h3 { margin-top: 20px; }\n';
    htmlListText += '    a { color: #4caf50; text-decoration: none; }\n';
    htmlListText += '    a:hover { text-decoration: underline; }\n';
    htmlListText += '    hr { border-color: #555; }\n';
    htmlListText += '    .media-links { margin-left: 20px; }\n';
    htmlListText += '    .board { margin-bottom: 30px; }\n';
    htmlListText += '    .thread { margin-bottom: 20px; padding-left: 20px; border-left: 3px solid #444; }\n';
    htmlListText += '  </style>\n</head>\n<body>\n';
    htmlListText += '  <h1>AnonIB Media Links</h1>\n';
    htmlListText += '  <p>Generated on ' + new Date().toISOString() + '</p>\n\n';
    
    if (imageHierarchy && imageHierarchy.boards.size > 0) {
      imageHierarchy.boards.forEach((threads, boardName) => {
        htmlListText += `  <div class="board">\n    <h2>Board: ${boardName}</h2>\n\n`;
        
        threads.forEach((threadData, threadId) => {
          htmlListText += `    <div class="thread">\n`;
          htmlListText += `      <h3>${threadData.title}</h3>\n`;
          htmlListText += `      <p>Thread URL: <a href="${threadData.url}" target="_blank">${threadData.url}</a></p>\n\n`;
          
          if (threadData.images && threadData.images.length > 0) {
            htmlListText += `      <h4>Images (${threadData.images.length}):</h4>\n      <div class="media-links">\n`;
            threadData.images.forEach(imgUrl => {
              htmlListText += `        <a href="${imgUrl}" target="_blank">${imgUrl.split('/').pop()}</a><br>\n`;
            });
            htmlListText += '      </div>\n\n';
          }
          
          if (threadData.videos && threadData.videos.length > 0) {
            htmlListText += `      <h4>Videos (${threadData.videos.length}):</h4>\n      <div class="media-links">\n`;
            threadData.videos.forEach(videoUrl => {
              htmlListText += `        <a href="${videoUrl}" target="_blank">${videoUrl.split('/').pop()}</a><br>\n`;
            });
            htmlListText += '      </div>\n\n';
          }
          
          htmlListText += '      <hr>\n    </div>\n\n';
        });
        
        htmlListText += '  </div>\n\n';
      });
    } else {
      htmlListText += '  <div class="media-links">\n';
      foundImages.forEach(url => {
        htmlListText += `    <a href="${url}" target="_blank">${url.split('/').pop()}</a><br>\n`;
      });
      htmlListText += '  </div>\n';
    }
    
    htmlListText += '</body>\n</html>';
    
    htmlListArea.value = htmlListText;
    
    const copyHtmlButton = document.createElement('button');
    copyHtmlButton.textContent = 'Copy HTML';
    copyHtmlButton.style.cssText = `
      margin-top: 10px;
      padding: 8px 15px;
      background-color: #2967a0;
      color: white;
      border: none;
      border-radius: 3px;
      cursor: pointer;
    `;
    copyHtmlButton.addEventListener('click', () => {
      htmlListArea.select();
      navigator.clipboard.writeText(htmlListArea.value).then(() => {
        copyHtmlButton.textContent = 'Copied!';
        setTimeout(() => {
          copyHtmlButton.textContent = 'Copy HTML';
        }, 2000);
      });
    });
    
    const downloadHtmlButton = document.createElement('button');
    downloadHtmlButton.textContent = 'Download HTML File';
    downloadHtmlButton.style.cssText = `
      margin-top: 10px;
      margin-left: 10px;
      padding: 8px 15px;
      background-color: #4caf50;
      color: white;
      border: none;
      border-radius: 3px;
      cursor: pointer;
    `;
    downloadHtmlButton.addEventListener('click', () => {
      const blob = new Blob([htmlListArea.value], { type: 'text/html' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'anonib_media_links.html';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    });
    
    htmlListContent.appendChild(htmlListArea);
    htmlListContent.appendChild(copyHtmlButton);
    htmlListContent.appendChild(downloadHtmlButton);
    
    // Create download script content
    const scriptArea = document.createElement('textarea');
    scriptArea.style.cssText = `
      width: 100%;
      height: 300px;
      background-color: #222;
      color: #ddd;
      border: 1px solid #555;
      padding: 10px;
      font-family: monospace;
      resize: vertical;
    `;
    
    let scriptText = '#!/bin/bash\n\n';
    scriptText += '# AnonIB Media Downloader Script\n';
    scriptText += '# Generated on ' + new Date().toISOString() + '\n\n';
    scriptText += '# Create output directory\n';
    scriptText += 'mkdir -p anonib_downloads\n\n';
    scriptText += '# Download function with retry\n';
    scriptText += 'download_file() {\n';
    scriptText += '  url="$1"\n';
    scriptText += '  output="$2"\n';
    scriptText += '  tries=0\n';
    scriptText += '  max_tries=3\n\n';
    scriptText += '  while [ $tries -lt $max_tries ]; do\n';
    scriptText += '    echo "Downloading $url to $output"\n';
    scriptText += '    curl -s -L --retry 3 --connect-timeout 10 -o "$output" "$url" && return 0\n';
    scriptText += '    tries=$((// Current Date and Time (UTC): 2025-03-13 21:07:02
// Current User's Login: JLSmart13

    scriptText += '  while [ $tries -lt $max_tries ]; do\n';
    scriptText += '    echo "Downloading $url to $output"\n';
    scriptText += '    curl -s -L --retry 3 --connect-timeout 10 -o "$output" "$url" && return 0\n';
    scriptText += '    tries=$((tries+1))\n';
    scriptText += '    if [ $tries -lt $max_tries ]; then\n';
    scriptText += '      echo "Retry $tries/$max_tries..."\n';
    scriptText += '      sleep 2\n';
    scriptText += '    fi\n';
    scriptText += '  done\n';
    scriptText += '  echo "Failed to download $url after $max_tries attempts"\n';
    scriptText += '  return 1\n';
    scriptText += '}\n\n';
    
    if (imageHierarchy && imageHierarchy.boards.size > 0) {
      let fileCount = 0;
      
      imageHierarchy.boards.forEach((threads, boardName) => {
        scriptText += `# Board: ${boardName}\n`;
        scriptText += `mkdir -p "anonib_downloads/${boardName}"\n\n`;
        
        threads.forEach((threadData, threadId) => {
          const safeThreadTitle = threadData.title.replace(/[^a-zA-Z0-9]/g, '_').substring(0, 30);
          
          scriptText += `# Thread: ${threadData.title} (${threadId})\n`;
          scriptText += `mkdir -p "anonib_downloads/${boardName}/${threadId}_${safeThreadTitle}"\n\n`;
          
          if (threadData.images && threadData.images.length > 0) {
            scriptText += `# Images (${threadData.images.length})\n`;
            threadData.images.forEach(imgUrl => {
              const filename = imgUrl.split('/').pop();
              scriptText += `download_file "${imgUrl}" "anonib_downloads/${boardName}/${threadId}_${safeThreadTitle}/img_${fileCount}_${filename}"\n`;
              fileCount++;
            });
            scriptText += '\n';
          }
          
          if (threadData.videos && threadData.videos.length > 0) {
            scriptText += `# Videos (${threadData.videos.length})\n`;
            threadData.videos.forEach(videoUrl => {
              const filename = videoUrl.split('/').pop();
              scriptText += `download_file "${videoUrl}" "anonib_downloads/${boardName}/${threadId}_${safeThreadTitle}/vid_${fileCount}_${filename}"\n`;
              fileCount++;
            });
            scriptText += '\n';
          }
          
          scriptText += '\n';
        });
        
        scriptText += '\n';
      });
    } else {
      scriptText += '# All files\n';
      foundImages.forEach((url, index) => {
        const filename = url.split('/').pop();
        scriptText += `download_file "${url}" "anonib_downloads/file_${index}_${filename}"\n`;
      });
    }
    
    scriptText += '\necho "Download complete!"\n';
    
    scriptArea.value = scriptText;
    
    const copyScriptButton = document.createElement('button');
    copyScriptButton.textContent = 'Copy Script';
    copyScriptButton.style.cssText = `
      margin-top: 10px;
      padding: 8px 15px;
      background-color: #2967a0;
      color: white;
      border: none;
      border-radius: 3px;
      cursor: pointer;
    `;
    copyScriptButton.addEventListener('click', () => {
      scriptArea.select();
      navigator.clipboard.writeText(scriptArea.value).then(() => {
        copyScriptButton.textContent = 'Copied!';
        setTimeout(() => {
          copyScriptButton.textContent = 'Copy Script';
        }, 2000);
      });
    });
    
    const downloadScriptButton = document.createElement('button');
    downloadScriptButton.textContent = 'Download Script';
    downloadScriptButton.style.cssText = `
      margin-top: 10px;
      margin-left: 10px;
      padding: 8px 15px;
      background-color: #4caf50;
      color: white;
      border: none;
      border-radius: 3px;
      cursor: pointer;
    `;
    downloadScriptButton.addEventListener('click', () => {
      const blob = new Blob([scriptArea.value], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'download_anonib_media.sh';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    });
    
    const scriptNote = document.createElement('p');
    scriptNote.textContent = 'Note: This bash script requires curl to be installed. Make the script executable with "chmod +x download_anonib_media.sh" before running.';
    scriptNote.style.cssText = `
      margin-top: 15px;
      font-size: 14px;
      color: #aaa;
    `;
    
    scriptContent.appendChild(scriptArea);
    scriptContent.appendChild(copyScriptButton);
    scriptContent.appendChild(downloadScriptButton);
    scriptContent.appendChild(scriptNote);
    
    // Add all tab contents to modal
    modalContent.appendChild(plainTextContent);
    modalContent.appendChild(htmlListContent);
    modalContent.appendChild(scriptContent);
    
    downloadModal.appendChild(modalContent);
    document.body.appendChild(downloadModal);
    
    // Add ESC key handler for modal
    document.addEventListener('keydown', function closeModalOnEsc(e) {
      if (e.key === 'Escape' && document.getElementById('downloadLinksModal')) {
        downloadModal.remove();
        document.removeEventListener('keydown', closeModalOnEsc);
      }
    });
  }
  
  // Final steps to integrate the script
  (function initializeScript() {
    // Set up auto-detection of AnonIB site
    if (isAnonibUrl(window.location.href)) {
      console.log('AnonIB site detected, initializing crawler...');
      
      // Initialize data structures
      initializeImageHierarchy();
      
      // Setup event listeners
      setupGlobalEventListeners();
      
      // Initialize UI
      initializeAnonibSiteHandler();
    }
  })();

  // This marks the end of the AnonIB crawler integrated functionality
}