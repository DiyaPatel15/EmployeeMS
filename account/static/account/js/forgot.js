// JavaScript code for showing/hiding forms
        document.addEventListener("DOMContentLoaded", () => {
            const forgotPasswordLink = document.getElementById("forgotPasswordLink");
            const backToLoginLink = document.getElementById("backToLogin");
            const loginForm = document.querySelector(".form.login");
            const forgotPasswordForm = document.querySelector(".form.forgot-password");

            forgotPasswordLink.addEventListener("click", () => {
                loginForm.style.display = "none";
                forgotPasswordForm.style.display = "block";
            });

            backToLoginLink.addEventListener("click", () => {
                loginForm.style.display = "block";
                forgotPasswordForm.style.display = "none";
            });
        });

        // JavaScript code for handling forgot password functionality
        function resetPassword() {
            // Fetch and validate input values
            const email = document.getElementById('forgot_email').value;

            // Perform necessary operations to reset password
            // You can use fetch or AJAX to send the data to the server
            // Implement the logic as per your backend requirements
            // Example: fetch('reset_password_url', { method: 'POST', body: JSON.stringify({ email }) })

            // Example success message
            alert("Password reset instructions sent to your email!");
        }
