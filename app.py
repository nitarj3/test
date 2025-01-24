import os
import re
import csv
from datetime import datetime
from flask import Flask, render_template, request, redirect, flash, send_file
import mysql.connector

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # For flash messages

# Database connection
def get_db_connection():
    conn = mysql.connector.connect(
        host='localhost',
        user='r4ve',
        password='123',
        database='cve_db'
    )
    return conn

# Function to validate CVE ID
def is_valid_cve_id(cve_id):
    # Regex for validating CVE ID format (CVE YYYY-NNNNN)
    pattern = r'^CVE \d{4}-\d{1,5}$'
    return re.match(pattern, cve_id) is not None

@app.route('/')
def index():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT * FROM cves')
    cves = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('index.html', cves=cves)

@app.route('/add', methods=['POST'])
def add_cve():
    if request.method == 'POST':
        cve_id = request.form['cve_id']
        
        # Validate CVE ID format
        if not is_valid_cve_id(cve_id):
            flash('Invalid CVE ID format. Must be in the format: CVE YYYY-NNNNN', 'error')
            return redirect('/')

        rule_name = request.form['rule_name']
        cve_description = request.form['cve_description']
        severity = request.form['severity']
        correlation_logic = request.form['correlation_logic']
        created_by = request.form['created_by']

        conn = get_db_connection()
        cursor = conn.cursor()

        # Check for duplicate CVE ID
        cursor.execute('SELECT * FROM cves WHERE cve_id = %s', (cve_id,))
        existing_cve = cursor.fetchone()

        if existing_cve:
            flash('Duplicate CVE ID! This CVE has already been added.', 'error')
            conn.close()
            return redirect('/')

        # Insert new CVE record if no duplicate found
        cursor.execute('''
          INSERT INTO cves (cve_id, rule_name, cve_description, severity, correlation_logic, created_by)
             VALUES (%s, %s, %s, %s, %s, %s)
        ''', (cve_id, rule_name, cve_description, severity, correlation_logic, created_by))

        conn.commit()
        cursor.close()
        conn.close()

        flash('CVE Rule added successfully!', 'success')

    return redirect('/')

@app.route('/edit/<cve_id>', methods=['GET', 'POST'])
def edit_cve(cve_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch the CVE record to edit
    cursor.execute('SELECT * FROM cves WHERE cve_id = %s', (cve_id,))
    cve = cursor.fetchone()

    if request.method == 'POST':
        # Get updated data from the form
        new_cve_id = request.form['cve_id']  # allow the user to update CVE ID
        
        # Validate the new CVE ID format
        if not is_valid_cve_id(new_cve_id):
            flash('Invalid CVE ID format. Must be in the format: CVE YYYY-NNNNN', 'error')
            return redirect('/')

        rule_name = request.form['rule_name']
        cve_description = request.form['cve_description']
        severity = request.form['severity']
        correlation_logic = request.form['correlation_logic']
        created_by = request.form['created_by']

        # If the CVE ID is changed, update it in the database
        if new_cve_id != cve_id:
            # Check if the new CVE ID already exists to avoid duplicates
            cursor.execute('SELECT * FROM cves WHERE cve_id = %s', (new_cve_id,))
            existing_cve = cursor.fetchone()
            if existing_cve:
                flash('Duplicate CVE ID! This CVE has already been added.', 'error')
                conn.close()
                return redirect('/')

            # Update the record with the new CVE ID
            cursor.execute('''
                UPDATE cves 
                SET cve_id = %s, rule_name = %s, cve_description = %s, severity = %s, 
                    correlation_logic = %s, created_by = %s 
                WHERE cve_id = %s
            ''', (new_cve_id, rule_name, cve_description, severity, correlation_logic, created_by, cve_id))

        else:
            # Update without changing CVE ID
            cursor.execute('''
                UPDATE cves 
                SET rule_name = %s, cve_description = %s, severity = %s, 
                    correlation_logic = %s, created_by = %s 
                WHERE cve_id = %s
            ''', (rule_name, cve_description, severity, correlation_logic, created_by, cve_id))

        conn.commit()
        flash('CVE Rule updated successfully!', 'success')
        return redirect('/')

    cursor.close()
    conn.close()

    return render_template('edit.html', cve=cve)

# Export data to CSV functionality remains the same
@app.route('/export', methods=['GET'])
def export_data():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT * FROM cves')
    cves = cursor.fetchall()
    cursor.close()
    conn.close()

    # Create the 'downloads' directory if it doesn't exist
    download_dir = 'downloads'
    if not os.path.exists(download_dir):
        os.makedirs(download_dir)

    # Create a CSV file and return it for download
    filename = f"cve_data_{datetime.now().strftime('%Y-%m-%d')}.csv"
    filepath = os.path.join(download_dir, filename)

    # Remove 'id' field if present in the cve dictionary
    for cve in cves:
        cve.pop('id', None)  # This removes the 'id' field if it exists

    # Define the fieldnames based on the columns in the cve table
    fieldnames = ['cve_id', 'rule_name', 'cve_description', 'severity', 'correlation_logic', 'created_by', 'created_at']

    with open(filepath, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for cve in cves:
            writer.writerow(cve)

    # Return the CSV file for download
    return send_file(filepath, as_attachment=True)

# New export to SQL functionality
@app.route('/export_sql', methods=['GET'])
def export_sql():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT * FROM cves')
    cves = cursor.fetchall()
    cursor.close()
    conn.close()

    # Create the 'downloads' directory if it doesn't exist
    download_dir = 'downloads'
    if not os.path.exists(download_dir):
        os.makedirs(download_dir)

    # Create the SQL file and return it for download
    filename = f"cve_data_{datetime.now().strftime('%Y-%m-%d')}.sql"
    filepath = os.path.join(download_dir, filename)

    with open(filepath, 'w') as sqlfile:
        for cve in cves:
            sqlfile.write(f"INSERT INTO cves (cve_id, rule_name, cve_description, severity, correlation_logic, created_by, created_at) VALUES ('{cve['cve_id']}', '{cve['rule_name']}', '{cve['cve_description']}', '{cve['severity']}', '{cve['correlation_logic']}', '{cve['created_by']}', '{cve['created_at']}');\n")

    # Return the SQL file for download
    return send_file(filepath, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
