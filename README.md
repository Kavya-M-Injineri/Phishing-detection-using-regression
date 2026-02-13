# Phishing Detection using Regression

This project is a comprehensive web application designed to detect phishing URLs using machine learning. It features a Flask backend, a user-friendly frontend, and a TensorFlow/Keras regression model that predicts the likelihood of a URL being a phishing attempt.

## Project Overview

The application analyzes URLs based on 48 specific features extracted from them. Instead of a simple "safe" or "phishing" classification, the model provides a continuous risk score (0 to 100%), allowing for more nuanced threat assessment.

Key features include:
-   **User Authentication**: Secure signup and login system to protect access.
-   **Real-time Prediction**: Analyze individual URLs instantly.
-   **Batch Processing**: Upload CSV files to analyze multiple URLs at once.
-   **Analytics Dashboard**: Visual insights into the dataset and model performance.
-   **Responsive Design**: A modern, dark-themed interface that works on all devices.

## Getting Started

Follow these instructions to set up and run the project on your local machine.

### Prerequisites

Ensure you have Python installed on your system. This project was built using Python 3.11.

### Installation

1.  Clone the repository or download the source code.
2.  Navigate to the project directory in your terminal.
3.  Install the required dependencies:

    ```bash
    pip install -r requirements.txt
    ```

### Training the Model

Before running the application, you need to train the machine learning model. The project includes a dedicated script for this:

```bash
python train_model.py
```

This script will:
-   Load the dataset (`Phishing_Legitimate_full.csv`).
-   Train the neural network for up to 20 epochs.
-   Save the trained model and feature scaler to the `saved_model/` directory.

### Running the Application

Once the model is trained, you can start the web server:

```bash
python app.py
```

The application will be accessible at `http://localhost:5000` in your web browser.

## Usage Guide

1.  **Register**: Create a new account on the Signup page.
2.  **Login**: Access your dashboard using your credentials.
3.  **Dashboard**: monitor the system status and view dataset statistics.
4.  **Predict**:
    -   Go to the "Predict" page.
    -   Enter the URL features manually to get a risk score.
    -   Or switch to "Batch Upload" to process a CSV file.
5.  **Analytics**: Explore the "Analytics" page to see which features contribute most to phishing detection and review the model's training history.

## Technologies Used

-   **Backend**: Flask (Python)
-   **Machine Learning**: TensorFlow, Keras, Scikit-learn, Pandas
-   **Frontend**: HTML, CSS, JavaScript (Chart.js for visualizations)
-   **Database**: SQLite (for user management)
-   **Authentication**: JSON Web Tokens (JWT)

## License

This project is open-source and available for educational and research purposes.
