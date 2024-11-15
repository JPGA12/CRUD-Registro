document.addEventListener("DOMContentLoaded", function() {
    const flashMessages = document.getElementById('flash-messages');
    if (flashMessages) {
        setTimeout(() => {
            flashMessages.style.transition = "opacity 0.5s";
            flashMessages.style.opacity = 0;
            setTimeout(() => { flashMessages.style.display = "none"; }, 500);
        }, 5000); // 5000 ms = 5 segundos
    }
});
