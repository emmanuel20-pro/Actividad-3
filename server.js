// Importar módulos necesarios
const express = require('express');
const fs = require('fs').promises;
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

// Configuración inicial
const app = express();
const PORT = 3000;
const SECRET_KEY = 'secreto';
const TAREAS_FILE = 'tareas.json';
const USERS_FILE = 'usuarios.json';

app.use(bodyParser.json());

// Middleware de autenticación
const autenticar = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ mensaje: 'Acceso denegado' });
    try {
        const verificado = jwt.verify(token, SECRET_KEY);
        req.usuario = verificado;
        next();
    } catch (err) {
        res.status(400).json({ mensaje: 'Token inválido' });
    }
};

// Función para leer datos de un archivo
const leerArchivo = async (archivo) => {
    try {
        const data = await fs.readFile(archivo, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        return [];
    }
};

// Función para escribir datos en un archivo
const escribirArchivo = async (archivo, datos) => {
    await fs.writeFile(archivo, JSON.stringify(datos, null, 2));
};

// Rutas de autenticación
app.post('/register', async (req, res) => {
    const { usuario, password } = req.body;
    const usuarios = await leerArchivo(USERS_FILE);
    if (usuarios.find(u => u.usuario === usuario)) {
        return res.status(400).json({ mensaje: 'Usuario ya existe' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    usuarios.push({ usuario, password: hashedPassword });
    await escribirArchivo(USERS_FILE, usuarios);
    res.json({ mensaje: 'Usuario registrado' });
});

app.post('/login', async (req, res) => {
    const { usuario, password } = req.body;
    const usuarios = await leerArchivo(USERS_FILE);
    const usuarioEncontrado = usuarios.find(u => u.usuario === usuario);
    if (!usuarioEncontrado || !(await bcrypt.compare(password, usuarioEncontrado.password))) {
        return res.status(400).json({ mensaje: 'Credenciales inválidas' });
    }
    const token = jwt.sign({ usuario }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
});

// Rutas de gestión de tareas
app.get('/tareas', autenticar, async (req, res) => {
    const tareas = await leerArchivo(TAREAS_FILE);
    res.json(tareas);
});

app.post('/tareas', autenticar, async (req, res) => {
    const { titulo, descripcion } = req.body;
    const tareas = await leerArchivo(TAREAS_FILE);
    const nuevaTarea = { id: Date.now(), titulo, descripcion };
    tareas.push(nuevaTarea);
    await escribirArchivo(TAREAS_FILE, tareas);
    res.json(nuevaTarea);
});

app.put('/tareas/:id', autenticar, async (req, res) => {
    const { id } = req.params;
    const { titulo, descripcion } = req.body;
    let tareas = await leerArchivo(TAREAS_FILE);
    const tareaIndex = tareas.findIndex(t => t.id == id);
    if (tareaIndex === -1) return res.status(404).json({ mensaje: 'Tarea no encontrada' });
    tareas[tareaIndex] = { ...tareas[tareaIndex], titulo, descripcion };
    await escribirArchivo(TAREAS_FILE, tareas);
    res.json(tareas[tareaIndex]);
});

app.delete('/tareas/:id', autenticar, async (req, res) => {
    const { id } = req.params;
    let tareas = await leerArchivo(TAREAS_FILE);
    tareas = tareas.filter(t => t.id != id);
    await escribirArchivo(TAREAS_FILE, tareas);
    res.json({ mensaje: 'Tarea eliminada' });
});

// Middleware de manejo de errores
app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ mensaje: 'Error interno del servidor' });
});

// Iniciar el servidor
app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
