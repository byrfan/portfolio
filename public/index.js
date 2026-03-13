console.log("loaded!");

// Load saved theme
(function() {
    const savedTheme = localStorage.getItem('theme') || 'dark-mode';
    document.body.className = savedTheme;
})();

window.toggleTheme = function () {
    if (document.body.classList.contains("dark-mode")) {
        document.body.className = "light-mode";
        localStorage.setItem("theme", "light-mode");
    } else {
        document.body.className = "dark-mode";
        localStorage.setItem("theme", "dark-mode");
    }
};

// ===== Cursor Glow =====
const cursorLight = document.getElementById("cursorLight");
if (cursorLight) {
    document.addEventListener("mousemove", (e) => {
        cursorLight.style.left = e.clientX + "px";
        cursorLight.style.top = e.clientY + "px";
    });
}

// ===== Typing Animation =====
const roles = [
    "Bachelor of Engineering Student @ QUT",
    "Computer & Software Systems Major",
    "Minor in Advanced Electrical",
    "Aspiring Software Engineer"
];

let roleIndex = 0;
let charIndex = 0;
const typingSpeed = 80;
const pauseTime = 2000;
const roleElement = document.getElementById("rotatingRole");

function typeRole() {
    const currentRole = roles[roleIndex];
    if (charIndex < currentRole.length) {
        roleElement.textContent += currentRole.charAt(charIndex);
        charIndex++;
        setTimeout(typeRole, typingSpeed);
    } else {
        setTimeout(deleteRole, pauseTime);
    }
}

function deleteRole() {
    const currentRole = roles[roleIndex];
    if (charIndex > 0) {
        roleElement.textContent = currentRole.substring(0, charIndex - 1);
        charIndex--;
        setTimeout(deleteRole, typingSpeed / 2);
    } else {
        roleIndex = (roleIndex + 1) % roles.length;
        setTimeout(typeRole, typingSpeed);
    }
}

// Start typing immediately
typeRole();
