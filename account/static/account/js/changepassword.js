document.getElementById("changePasswordForm").addEventListener("submit", function(event) {
    event.preventDefault();
    var newPassword = document.getElementById("newPassword").value;
    var confirmPassword = document.getElementById("confirmPassword").value;

    if (newPassword !== confirmPassword) {
        document.getElementById("message").innerHTML = "New password and confirm password do not match";
        return;
    }

    // Code to send password change request to server
    // You can use fetch or AJAX to send the data to the server
    // Example: fetch('change_password_url', { method: 'POST', body: JSON.stringify({ currentPassword, newPassword }) })
    // Example success message
    document.getElementById("message").innerHTML = "Password changed successfully";
});
