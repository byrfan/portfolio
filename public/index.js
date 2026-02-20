console.log("loaded!");

window.toggleTheme = function () {
    const btns = document.querySelectorAll(".socials .btn");
    
    if (document.body.classList.contains("dark-mode")) {
        document.body.className = "light-mode";
        localStorage.setItem("theme", "light-mode");

        // Swap social buttons to dark-outline in light mode
        btns.forEach(btn => btn.classList.replace("btn-outline-light", "btn-outline-dark"));

    } else {
        document.body.className = "dark-mode";
        localStorage.setItem("theme", "dark-mode");

        // Swap social buttons back to light-outline in dark mode
        btns.forEach(btn => btn.classList.replace("btn-outline-dark", "btn-outline-light"));
    }
};


// ===== Cursor Glow =====
const cursorLight = document.getElementById("cursorLight");
document.addEventListener("mousemove", (e) => {
    cursorLight.style.left = e.clientX + "px";
    cursorLight.style.top = e.clientY + "px";
});

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


