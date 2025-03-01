from email_checker import EmailChecker

def main():
    checker = EmailChecker()
    email = "jocen88343@calmpros.com"
    
    success, results = checker.verify_email(email)
    
    if isinstance(results, str):
        print(f"Error: {results}")
    else:
        print(f"Email verification successful: {success}")
        print("\nDetailed Results:")
        for key, value in results.items():
            print(f"{key}: {value}")

if __name__ == "__main__":
    main() 