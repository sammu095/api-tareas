
const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;

const SECRET = 'clave_secreta_actividad_fullstack';

const ARCHIVO = path.join(__dirname, 'tareas.json');
const ARCHIVO_USUARIOS = path.join(__dirname, 'usuarios.json');

app.use(express.json());

// =====================================
// FUNCIONES PARA MANEJAR TAREAS
// =====================================

async function obtenerTareas() {
    const data = await fs.readFile(ARCHIVO, 'utf8');
    return JSON.parse(data);
}

async function guardarTareas(tareas) {
    await fs.writeFile(
        ARCHIVO,
        JSON.stringify(tareas, null, 2)
    );
}

// =====================================
// FUNCIONES PARA MANEJAR USUARIOS
// =====================================

async function obtenerUsuarios() {
    const data = await fs.readFile(ARCHIVO_USUARIOS, 'utf8');
    return JSON.parse(data);
}

async function guardarUsuarios(usuarios) {
    await fs.writeFile(
        ARCHIVO_USUARIOS,
        JSON.stringify(usuarios, null, 2)
    );
}

// =====================================
// MIDDLEWARE DE VALIDACIÓN
// =====================================

function validarTarea(req, res, next) {
    const { titulo, descripcion } = req.body;

    if (
        typeof titulo !== 'string' ||
        !titulo.trim() ||
        typeof descripcion !== 'string' ||
        !descripcion.trim()
    ) {
        return res.status(400).json({
            error: 'El título y la descripción son obligatorios y deben ser texto'
        });
    }

    next();
}

// =====================================
// REGISTRO DE USUARIOS
// =====================================

app.post('/register', async (req, res, next) => {
    try {
        const { usuario, password } = req.body;

        if (
            typeof usuario !== 'string' ||
            !usuario.trim() ||
            typeof password !== 'string' ||
            password.length < 6
        ) {
            return res.status(400).json({
                error: 'Ingresa un usuario y una contraseña de al menos 6 caracteres'
            });
        }

        const usuarios = await obtenerUsuarios();

        const existe = usuarios.find(
            u => u.usuario === usuario.trim()
        );

        if (existe) {
            return res.status(409).json({
                error: 'El usuario ya existe'
            });
        }

        const passwordEncriptada = await bcrypt.hash(password, 10);

        usuarios.push({
            usuario: usuario.trim(),
            password: passwordEncriptada
        });

        await guardarUsuarios(usuarios);

        res.status(201).json({
            mensaje: 'Usuario registrado correctamente'
        });

    } catch (error) {
        next(error);
    }
});

// =====================================
// INICIO DE SESIÓN
// =====================================

app.post('/login', async (req, res, next) => {
    try {
        const { usuario, password } = req.body;

        if (
            typeof usuario !== 'string' ||
            typeof password !== 'string'
        ) {
            return res.status(400).json({
                error: 'Debes proporcionar usuario y contraseña'
            });
        }

        const usuarios = await obtenerUsuarios();

        const encontrado = usuarios.find(
            u => u.usuario === usuario.trim()
        );

        if (!encontrado) {
            return res.status(401).json({
                error: 'Usuario o contraseña incorrectos'
            });
        }

        const valido = await bcrypt.compare(
            password,
            encontrado.password
        );

        if (!valido) {
            return res.status(401).json({
                error: 'Usuario o contraseña incorrectos'
            });
        }

        const token = jwt.sign(
            { usuario: encontrado.usuario },
            SECRET,
            { expiresIn: '1h' }
        );

        res.json({
            mensaje: 'Inicio de sesión exitoso',
            token
        });

    } catch (error) {
        next(error);
    }
});

// =====================================
// MIDDLEWARE DE AUTENTICACIÓN JWT
// =====================================

function autenticarToken(req, res, next) {
    const autorizacion = req.headers.authorization;

    if (!autorizacion || !autorizacion.startsWith('Bearer ')) {
        return res.status(401).json({
            error: 'Se requiere un token de autenticación'
        });
    }

    const token = autorizacion.split(' ')[1];

    jwt.verify(token, SECRET, (error, usuario) => {
        if (error) {
            return res.status(403).json({
                error: 'Token inválido o expirado'
            });
        }

        req.usuario = usuario;
        next();
    });
}

// =====================================
// GET: CONSULTAR TODAS LAS TAREAS
// =====================================

app.get('/tareas', autenticarToken, async (req, res, next) => {
    try {
        const tareas = await obtenerTareas();
        res.json(tareas);

    } catch (error) {
        next(error);
    }
});

// =====================================
// POST: CREAR UNA TAREA
// =====================================

app.post(
    '/tareas',
    autenticarToken,
    validarTarea,
    async (req, res, next) => {
        try {
            const { titulo, descripcion } = req.body;

            const tareas = await obtenerTareas();

            const nuevaTarea = {
                id: Date.now().toString(),
                titulo: titulo.trim(),
                descripcion: descripcion.trim(),
                completada: false
            };

            tareas.push(nuevaTarea);

            await guardarTareas(tareas);

            res.status(201).json(nuevaTarea);

        } catch (error) {
            next(error);
        }
    }
);

// =====================================
// PUT: ACTUALIZAR UNA TAREA
// =====================================

app.put(
    '/tareas/:id',
    autenticarToken,
    validarTarea,
    async (req, res, next) => {
        try {
            const { id } = req.params;
            const { titulo, descripcion, completada } = req.body;

            const tareas = await obtenerTareas();

            const indice = tareas.findIndex(
                tarea => tarea.id === id
            );

            if (indice === -1) {
                return res.status(404).json({
                    error: 'Tarea no encontrada'
                });
            }

            tareas[indice].titulo = titulo.trim();
            tareas[indice].descripcion = descripcion.trim();

            if (completada !== undefined) {
                if (typeof completada !== 'boolean') {
                    return res.status(400).json({
                        error: 'El campo completada debe ser booleano'
                    });
                }

                tareas[indice].completada = completada;
            }

            await guardarTareas(tareas);

            res.json({
                mensaje: 'Tarea actualizada correctamente',
                tarea: tareas[indice]
            });

        } catch (error) {
            next(error);
        }
    }
);

// =====================================
// DELETE: ELIMINAR UNA TAREA
// =====================================

app.delete('/tareas/:id', autenticarToken, async (req, res, next) => {
    try {
        const { id } = req.params;

        const tareas = await obtenerTareas();

        const nuevasTareas = tareas.filter(
            tarea => tarea.id !== id
        );

        if (tareas.length === nuevasTareas.length) {
            return res.status(404).json({
                error: 'Tarea no encontrada'
            });
        }

        await guardarTareas(nuevasTareas);

        res.json({
            mensaje: 'Tarea eliminada correctamente'
        });

    } catch (error) {
        next(error);
    }
});

// =====================================
// MIDDLEWARE PARA RUTAS NO ENCONTRADAS
// =====================================

app.use((req, res, next) => {
    const error = new Error('Ruta no encontrada');
    error.status = 404;
    next(error);
});

// =====================================
// MIDDLEWARE GENERAL DE ERRORES
// =====================================

app.use((error, req, res, next) => {
    console.error('Error detectado:', error.message);

    res.status(error.status || 500).json({
        error: error.message || 'Error interno del servidor'
    });
});

// =====================================
// INICIAR SERVIDOR
// =====================================

app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});
