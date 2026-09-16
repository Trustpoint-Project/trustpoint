// based on theme.js from Django admin, no need to reinvent the wheel
// Copyright (c) Django Software Foundation and individual contributors.
// Licensed under the BSD 3-clause License

{
    function setTheme(mode) {
        if (mode !== "light" && mode !== "dark") {
            const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
            mode = prefersDark ? "dark" : "light";
        }
        document.documentElement.dataset.theme = mode;
        document.documentElement.dataset.bsTheme = mode;
        localStorage.setItem("theme", mode);
    }

    function cycleTheme() {
        const currentTheme = localStorage.getItem("theme") || "light";
        
        if (currentTheme === "light") {
            setTheme("dark");
        } else {
            setTheme("light");
        }
    }

    function initTheme() {
        // Authenticated users get the server-persisted preference on every page load.
        const serverTheme = document.documentElement.dataset.userTheme;
        if (serverTheme === "light" || serverTheme === "dark") {
            setTheme(serverTheme);
            return;
        }

        // Anonymous pages use the browser preference when no local choice exists.
        const currentTheme = localStorage.getItem("theme");
        currentTheme ? setTheme(currentTheme) : setTheme("auto");
    }

    function setupTheme() {
        // Attach event handlers for toggling themes
        const buttons = document.getElementsByClassName("theme-toggle");
        Array.from(buttons).forEach((btn) => {
            btn.addEventListener("click", cycleTheme);
        });

        const selectors = document.querySelectorAll("[data-theme-selector]");
        selectors.forEach((selector) => {
            selector.addEventListener("change", (event) => {
                setTheme(event.target.value);
            });
        });
    }

    window.addEventListener('DOMContentLoaded', function() {
        initTheme();
        setupTheme();
    });
}