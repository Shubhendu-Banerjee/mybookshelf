document.addEventListener('DOMContentLoaded', () => {
    const titleInput = document.querySelector('input[name="title"]');
    const authorInput = document.querySelector('input[name="author"]');
    const genreInput = document.querySelector('input[name="genre"]');
    
    const suggestionBox = document.createElement('div');
    suggestionBox.style.position = 'absolute';
    suggestionBox.style.top = (titleInput.offsetHeight + 4) + 'px'; // just below input with some spacing
    suggestionBox.style.left = '0';
    suggestionBox.style.right = '0'; // stretch to match input width
    suggestionBox.style.backgroundColor = '#fff';
    suggestionBox.style.border = '1px solid #ccc';
    suggestionBox.style.borderRadius = '4px';
    suggestionBox.style.boxShadow = '0 4px 8px rgba(0,0,0,0.1)';
    suggestionBox.style.maxHeight = '200px';
    suggestionBox.style.overflowY = 'auto';
    suggestionBox.style.zIndex = 1000;
    suggestionBox.style.fontFamily = 'Segoe UI, Tahoma, Geneva, Verdana, sans-serif';
    suggestionBox.style.display = 'none';
  
    // Ensure parent is relative for absolute positioning
    titleInput.parentNode.style.position = 'relative';
    titleInput.parentNode.appendChild(suggestionBox);
  
    function positionSuggestionBox() {
      const rect = titleInput.getBoundingClientRect();
      suggestionBox.style.width = rect.width + 'px';
    }
  
    window.addEventListener('resize', positionSuggestionBox);
    window.addEventListener('scroll', positionSuggestionBox);
    positionSuggestionBox();
  
    titleInput.addEventListener('input', async () => {
      const query = titleInput.value.trim();
      if (query.length < 3) {
        suggestionBox.style.display = 'none';
        return;
      }
  
      try {
        const response = await fetch(`https://www.googleapis.com/books/v1/volumes?q=intitle:${encodeURIComponent(query)}&maxResults=5`);
        const data = await response.json();
  
        suggestionBox.innerHTML = '';
        if (data.items && data.items.length > 0) {
          data.items.forEach(item => {
            const div = document.createElement('div');
            div.textContent = item.volumeInfo.title;
            div.style.padding = '8px 12px';
            div.style.borderBottom = '1px solid #eee';
            div.style.cursor = 'pointer';
            div.style.transition = 'background-color 0.2s ease';
  
            div.addEventListener('mouseenter', () => {
              div.style.backgroundColor = '#f0f8ff';
            });
            div.addEventListener('mouseleave', () => {
              div.style.backgroundColor = 'white';
            });
  
            div.addEventListener('click', () => {
              titleInput.value = item.volumeInfo.title || '';
              authorInput.value = (item.volumeInfo.authors && item.volumeInfo.authors[0]) || '';
              genreInput.value = (item.volumeInfo.categories && item.volumeInfo.categories[0]) || '';
              suggestionBox.style.display = 'none';
            });
  
            suggestionBox.appendChild(div);
          });
          suggestionBox.style.display = 'block';
        } else {
          suggestionBox.style.display = 'none';
        }
      } catch (err) {
        console.error('Error fetching from Google Books API:', err);
        suggestionBox.style.display = 'none';
      }
    });
  
    document.addEventListener('click', (e) => {
      if (!titleInput.contains(e.target) && !suggestionBox.contains(e.target)) {
        suggestionBox.style.display = 'none';
      }
    });
  });  