document.addEventListener("DOMContentLoaded", function () {

    const exampleSerialInput = document.getElementById("example-serial");
    const regexList = document.getElementById("regex-list");
    const regexOptionsContainer = document.getElementById("regex-options"); // The div to show/hide
    const serialNumberPatternInput = document.getElementById("id_serial_number_pattern"); // Form field

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

        let segments = example.split(/([-_:.])/); // Split by special characters while keeping them
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
            if (index % 2 === 0) { // Skip special characters
                let remaining = remainingPattern.slice(index + 1).join("");
                let separator = (remaining && !remaining.startsWith("-") && !remaining.startsWith("_") && !remaining.startsWith(".") && !remaining.startsWith(":")) ? "-" : "";
                lastExactMatch = `^${fixedPart}${remaining ? separator + remaining : ""}$`; // Store last match
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
            ...exactBlockRegexList, // Last entry will be "Full Serial"
            {label: "Any Character (Matches Anything)", regex: anyCharacter}
        ];
    }

    if (exampleSerialInput && regexList && regexOptionsContainer && serialNumberPatternInput) {
        exampleSerialInput.addEventListener("input", function () {
            let exampleSerial = exampleSerialInput.value.trim();
            regexList.innerHTML = ""; // Clear previous results

            if (exampleSerial.length > 0) {
                let variations = generateRegexVariations(exampleSerial);

                regexOptionsContainer.style.display = "block"; // ✅ Show regex options

                variations.forEach((variation, index) => {
                    let listItem = document.createElement("li");
                    listItem.classList.add("list-group-item", "regex-option");
                    listItem.innerHTML = `<strong>${variation.label}:</strong> <code>${variation.regex}</code>`;

                    // ✅ Allow selection of regex
                    listItem.addEventListener("click", function () {
                        serialNumberPatternInput.value = variation.regex;
                        document.querySelectorAll(".regex-option").forEach(el => el.classList.remove("active"));
                        listItem.classList.add("active"); // Highlight selected
                    });

                    regexList.appendChild(listItem);

                    // ✅ Auto-fill the first regex by default
                    if (index === 0) {
                        serialNumberPatternInput.value = variation.regex;
                    }
                });
            } else {
                regexOptionsContainer.style.display = "none"; // ✅ Hide if input is empty
                serialNumberPatternInput.value = ""; // Clear input
            }
        });
    } else {
        console.error("Error: Form elements not found in DOM.");
    }
});
