function openPopup(videoId) {
    const form = document.getElementById("share-form");
    form.action = `/share/${videoId}`;
    document.getElementById("popup").classList.remove("hidden");
}

function closePopup() {
    document.getElementById("popup").classList.add("hidden");
}

