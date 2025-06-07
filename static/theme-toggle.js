document.addEventListener('DOMContentLoaded', () => {
    const toggleButton = document.getElementById('darkModeToggle');

    if (toggleButton) {
        // Function to apply theme based on local storage or system preference
        const applyTheme = (theme) => {
            if (theme === 'dark') {
                document.body.classList.add('dark-mode');
            } else {
                document.body.classList.remove('dark-mode');
            }
        };

        // Initial theme setup: check local storage first, then system preference
        const savedTheme = localStorage.getItem('theme');
        if (savedTheme) {
            applyTheme(savedTheme);
        } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
            // Check system preference if no theme saved
            applyTheme('dark');
        } else {
            applyTheme('light'); // Default to light if nothing is preferred
        }

        // Toggle functionality
        toggleButton.addEventListener('click', () => {
            if (document.body.classList.contains('dark-mode')) {
                document.body.classList.remove('dark-mode');
                localStorage.setItem('theme', 'light');
            } else {
                document.body.classList.add('dark-mode');
                localStorage.setItem('theme', 'dark');
            }
        });
    }
});