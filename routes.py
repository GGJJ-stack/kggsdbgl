@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('login'))