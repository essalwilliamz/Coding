// admin.js
class AdminPanel {
    constructor() {
        this.token = localStorage.getItem('token');
        this.baseUrl = 'http://localhost:5000/api';
    }

    async login(username, password) {
        try {
            const response = await fetch(`${this.baseUrl}/auth/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password })
            });

            const data = await response.json();
            if (response.ok) {
                localStorage.setItem('token', data.token);
                this.token = data.token;
                return true;
            }
            throw new Error(data.message);
        } catch (error) {
            console.error('Login error:', error);
            throw error;
        }
    }

    async addProject(formData) {
        try {
            const response = await fetch(`${this.baseUrl}/projects`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.token}`
                },
                body: formData // FormData for file upload
            });

            if (!response.ok) throw new Error('Failed to add project');
            return await response.json();
        } catch (error) {
            console.error('Add project error:', error);
            throw error;
        }
    }

    async updateProject(id, formData) {
        try {
            const response = await fetch(`${this.baseUrl}/projects/${id}`, {
                method: 'PUT',
                headers: {
                    'Authorization': `Bearer ${this.token}`
                },
                body: formData
            });

            if (!response.ok) throw new Error('Failed to update project');
            return await response.json();
        } catch (error) {
            console.error('Update project error:', error);
            throw error;
        }
    }

    async deleteProject(id) {
        try {
            const response = await fetch(`${this.baseUrl}/projects/${id}`, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });

            if (!response.ok) throw new Error('Failed to delete project');
            return await response.json();
        } catch (error) {
            console.error('Delete project error:', error);
            throw error;
        }
    }

    async getMessages() {
        try {
            const response = await fetch(`${this.baseUrl}/contact`, {
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });

            if (!response.ok) throw new Error('Failed to fetch messages');
            return await response.json();
        } catch (error) {
            console.error('Get messages error:', error);
            throw error;
        }
    }
}

// Initialize admin panel
const admin = new AdminPanel();