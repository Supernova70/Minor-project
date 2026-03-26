import sys
import os

# Add the project directory to sys.path to import app modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.engines.text_analyzer import get_text_analyzer

def test_ml_engine():
    print("Initializing TextAnalyzer...")
    analyzer = get_text_analyzer()
    
    if analyzer.model is None:
        print("ERROR: Model failed to load.")
        sys.exit(1)
        
    print("Model loaded successfully. Running tests...")
    
    test_cases = [
        "Dear customer, your account has been suspended. Please click here to verify your identity.",
        "Hey team, attached is the sprint planning document for next week. Let me know if you have any questions.",
        "URGENT: WINNER WINNER! You have won a $1000 gift card. Claim now at http://fake-website.com/claim"
    ]
    
    for i, text in enumerate(test_cases, 1):
        print(f"\nTest Case {i}:")
        print(f"Text: '{text}'")
        result = analyzer.analyze(text)
        print(f"Result: {result.label} (Confidence: {result.confidence}%)")
        print("-" * 40)

if __name__ == "__main__":
    test_ml_engine()
