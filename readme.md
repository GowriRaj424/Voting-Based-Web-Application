# Voting-Based Web Application

This web application allows users to create and vote on polls. Admin users can create and manage polls, while regular users can vote on active polls. This application is built using **Flask** and **SQLAlchemy** and uses **Flask-Login** for user authentication.

---

## Prerequisites

Before you begin, ensure you have the following installed:

- **Python 3.x** or higher
- **Pip** (Python package installer)
- **SQLite** (comes with Python by default)

You will also need to create a virtual environment.

---

## Setting up the Environment

### 1. Create a Virtual Environment

In your project folder, create a virtual environment named `env`:

```bash
python -m venv env
```

## 2. Activate the Virtual Environment

```
.\\env\\Scripts\\activate
```

# 3. Install Dependencies

```
pip install -r requirements.txt
```

## 4. Initialize the Database

1. Initialize the migrations folder:

```
flask db init
```

2. Create the first migration:

```
flask db migrate -m "Initial migration"
```

3. Apply the migration:

```
flask db upgrade
```

## Running the Application

```
flask run
```
