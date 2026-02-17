document.addEventListener("DOMContentLoaded", function () {

    const exampleSerialInput = document.getElementById("example-serial");
    const regexList = document.getElementById("regex-list");
    const regexOptionsContainer = document.getElementById("regex-options");
    const serialNumberPatternInput = document.getElementById("id_serial_number_pattern");

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function detectPattern(segment) {
        if (/^\d+$/.test(segment)) return `\\d{${segment.length}}`;
        if (/^[A-Z]+$/.test(segment)) return `[A-Z]{${segment.length}}`;
        if (/^[a-z]+$/.test(segment)) return `[a-z]{${segment.length}}`;
        if (/^[A-Z0-9]+$/.test(segment)) return `[A-Z0-9]{${segment.length}}`;
        if (/^[a-z0-9]+$/.test(segment)) return `[a-z0-9]{${segment.length}}`;
        return segment;
    }

    function generateRegexVariations(example) {
        let regexParts = [];
        let strictRegex = [];
        let relaxedRegex = [];
        let exactBlockRegexList = [];

        let segments = example.split(/([-_:.])/);
        let remainingPattern = [];

        segments.forEach(segment => {
            let detectedPattern = detectPattern(segment);
            strictRegex.push(detectedPattern);
            let relaxedPattern = detectedPattern.replace(/\[A-Z\]/g, '[A-Za-z]').replace(/\[a-z\]/g, '[A-Za-z]');
            relaxedRegex.push(relaxedPattern);
            remainingPattern.push(detectedPattern);
        });

        let fixedPart = "";
        let lastExactMatch = "";
        segments.forEach((segment, index) => {
            fixedPart += segment;
            if (index % 2 === 0) { 
                let remaining = remainingPattern.slice(index + 1).join("");
                let separator = (remaining && !remaining.startsWith("-") && !remaining.startsWith("_") && !remaining.startsWith(".") && !remaining.startsWith(":")) ? "-" : "";
                lastExactMatch = `^${fixedPart}${remaining ? separator + remaining : ""}$`;
                exactBlockRegexList.push({
                    label: `Exact Block Matching (First ${index / 2 + 1} Block${index > 0 ? "s" : ""})`,
                    regex: lastExactMatch
                });
            }
        });

        let anyCharacter = "^.*$";

        return [
            {label: "Strict Matching (Exact Upper/Lower Rules)", regex: `^${strictRegex.join("")}$`},
            {label: "Relaxed Matching (Allows Upper/Lower Mix)", regex: `^${relaxedRegex.join("")}$`},
            ...exactBlockRegexList, 
            {label: "Any Character (Matches Anything)", regex: anyCharacter}
        ];
    }

    if (exampleSerialInput && regexList && regexOptionsContainer && serialNumberPatternInput) {
        exampleSerialInput.addEventListener("input", function () {
            let exampleSerial = exampleSerialInput.value.trim();
            regexList.innerHTML = "";

            if (exampleSerial.length > 0) {
                let variations = generateRegexVariations(exampleSerial);

                regexOptionsContainer.style.display = "block";

                variations.forEach((variation, index) => {
                    let listItem = document.createElement("li");
                    listItem.classList.add("list-group-item", "regex-option");
                    listItem.innerHTML = `<strong>${escapeHtml(variation.label)}:</strong> <code>${escapeHtml(variation.regex)}</code>`;

                    listItem.addEventListener("click", function () {
                        serialNumberPatternInput.value = variation.regex;
                        document.querySelectorAll(".regex-option").forEach(el => el.classList.remove("active"));
                        listItem.classList.add("active");
                    });

                    regexList.appendChild(listItem);

                    if (index === 0) {
                        serialNumberPatternInput.value = variation.regex;
                    }
                });
            } else {
                regexOptionsContainer.style.display = "none"; 
                serialNumberPatternInput.value = "";
            }
        });
    } else {
        console.error("Error: Form elements not found in DOM.");
    }
});
