import streamlit as st
import re

def check_password_strength(password):
    if len(password) < 8:
        return "Weak: Password must be at least 8 characters long."
    if not re.search("[a-z]", password):
        return "Weak: Password must contain at least one lowercase letter."
    if not re.search("[A-Z]", password):
        return "Weak: Password must contain at least one uppercase letter."
    if not re.search("[0-9]", password):
        return "Weak: Password must contain at least one digit."
    if not re.search("[@#$%^&+=]", password):
        return "Weak: Password must contain at least one special character."
    return "Strong: Your password is strong!"

def main():
    st.title("Password Strength Checker")
    
    password = st.text_input("Enter your password:", type="password")
    
    if st.button("Check Password Strength"):
        if password:
            strength = check_password_strength(password)
            st.success(strength)
        else:
            st.error("Please enter a password.")

if __name__ == "__main__":
    
    main()