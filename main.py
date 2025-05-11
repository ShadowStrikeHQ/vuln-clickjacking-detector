import argparse
import requests
import logging
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description='Detects Clickjacking vulnerability in a website.')
    parser.add_argument('url', type=str, help='The URL of the website to check.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output (debug logging).')
    return parser

def check_clickjacking(url):
    """
    Checks for clickjacking vulnerability by analyzing HTTP headers.
    
    Args:
        url (str): The URL of the website to check.
        
    Returns:
        tuple: (vulnerable (bool), headers (dict), messages (list))
    """
    try:
        # Sanitize URL (Basic input validation)
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url  # Default to HTTP if no protocol specified
        
        # Send a GET request to the URL
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        
        headers = response.headers
        x_frame_options = headers.get('X-Frame-Options')
        content_security_policy = headers.get('Content-Security-Policy')
        
        vulnerable = True
        messages = []
        
        if x_frame_options:
            messages.append(f"X-Frame-Options header found: {x_frame_options}")
            if x_frame_options.lower() in ['deny', 'sameorigin']:
                vulnerable = False
                messages.append("Website is likely protected against clickjacking by X-Frame-Options.")
        else:
            messages.append("X-Frame-Options header is missing.")
            
        if content_security_policy:
            messages.append(f"Content-Security-Policy header found: {content_security_policy}")
            frame_ancestors_present = "frame-ancestors" in content_security_policy.lower()
            frame_src_present = "frame-src" in content_security_policy.lower()

            if frame_ancestors_present or frame_src_present:
                vulnerable = False
                messages.append("Website is likely protected against clickjacking by Content-Security-Policy.")
            else:
                messages.append("Content-Security-Policy header does not appear to have clickjacking protection.")
        else:
            messages.append("Content-Security-Policy header is missing.")
        
        if vulnerable:
            messages.append("Website may be vulnerable to clickjacking.")
            messages.append("Mitigation: Implement X-Frame-Options or Content-Security-Policy to prevent framing.")
        
        return vulnerable, headers, messages
    except requests.exceptions.RequestException as e:
        logging.error(f"Request error: {e}")
        return True, {}, [f"Error during request: {e}"]  # Treat as vulnerable on error.
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")
        return True, {}, [f"An unexpected error occurred: {e}"]   # Treat as vulnerable on error.

def main():
    """
    Main function to execute the clickjacking detection tool.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose mode enabled.")
    
    url = args.url

    if not url:
        print("Error: URL is required.")
        sys.exit(1)

    logging.info(f"Checking URL: {url}")
    vulnerable, headers, messages = check_clickjacking(url)
    
    print(f"Clickjacking Detection Results for {url}:")
    for message in messages:
        print(message)
    
    if vulnerable:
        print("\nWARNING: The website appears to be vulnerable to clickjacking!")
    else:
        print("\nThe website appears to be protected against clickjacking.")

    logging.info("Scan completed.")

if __name__ == "__main__":
    main()