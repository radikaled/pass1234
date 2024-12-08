function toggleVisibility(cred, icon) {
    const credField = document.getElementById(cred);
    const iconField = document.getElementById(icon);

    if (credField.type === "password") {
        credField.type = "text";
        iconField.classList.remove("fa-eye");
        iconField.classList.add("fa-eye-slash");
    } else {
        credField.type = "password";
        iconField.classList.remove("fa-eye-slash");
        iconField.classList.add("fa-eye");
    }
}