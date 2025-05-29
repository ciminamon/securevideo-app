function openPopup(videoId) {
    const form = document.getElementById("share-form");
    form.action = `/share/${videoId}`;
    document.getElementById("popup").classList.remove("hidden");
}

function closePopup() {
    document.getElementById("popup").classList.add("hidden");
}

function hideQRCode() {
    const qrModal = document.getElementById("qrModal");
    qrModal.classList.add("hidden");
    document.getElementById("qrImage").src = ""; // Clear QR
    document.getElementById("qrStatus").textContent = ""; // Clear status
    document.getElementById("qrSpinner").classList.add("hidden"); // Hide spinner
}

function showQRCode(type, filename) {
    const qrModal = document.getElementById("qrModal");
    const qrImage = document.getElementById("qrImage");
    const qrStatus = document.getElementById("qrStatus");
    const qrSpinner = document.getElementById("qrSpinner");
    const downloadBtn = document.getElementById("downloadKeyBundle");
    
    // Reset classes and status
    qrStatus.classList.remove("text-red-600");
    qrImage.classList.add("hidden");
    downloadBtn.classList.add("hidden");
    
    // Show modal and loading state
    qrModal.classList.remove("hidden");
    qrSpinner.classList.remove("hidden");
    qrStatus.textContent = "Generating QR Code...";
    
    // Generate QR Code
    let route = `/qr/bundle/${filename}`;
    
    // Load QR Code
    qrImage.onload = function() {
        qrSpinner.classList.add("hidden");
        qrImage.classList.remove("hidden");
        qrStatus.textContent = "Scan QR code to download keys";
        downloadBtn.classList.remove("hidden");
        downloadBtn.href = `/download-key-bundle/${filename}`;
    };
    
    qrImage.onerror = function() {
        qrSpinner.classList.add("hidden");
        qrStatus.textContent = "Failed to generate QR code. Please try again.";
        qrStatus.classList.add("text-red-600");
    };
    
    qrImage.src = route;
}

