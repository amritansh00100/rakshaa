const bcrypt = require('bcrypt');  // password hashing
const cors = require('cors');      // any port working
const jwt = require('jsonwebtoken');  
require('dotenv').config();        // for using .env file
const express = require('express'); // express framework
const { GoogleGenerativeAI } = require("@google/generative-ai"); // for chatbot
const createGraph = require('ngraph.graph');  // graph or map use
const ngraphPath = require('ngraph.path'); // Renamed from 'path' to avoid conflict with Node.js path module
const path = require('path'); // Node.js path module for file serving

const multer = require('multer');
// FIX: Added 5MB limit to prevent RAM crash
const upload = multer({ 
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 } 
});

// --- SUPABASE CONNECTION SETUP ---
const { createClient } = require('@supabase/supabase-js');
const supabase = createClient(
    process.env.SUPABASE_URL, 
    process.env.SUPABASE_ANON_KEY
);

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(cors({
    origin: '*', // Allows requests from any website or local file
    methods: ['GET', 'POST', 'PUT', 'DELETE'], // Allowed HTTP actions
    allowedHeaders: ['Content-Type', 'Authorization'], // Allows sending JSON and Login Tokens
    credentials: true // Optional: allows cookies if you decide to use them later
}));

// 1. Serve static files (this allows your PWA files to be accessible)
app.use(express.static(path.join(__dirname, '/')));

// 2. Route for your PWA homepage
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// AI Initialization
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

// --- Middleware: JWT Authentication ---
function authenticateToken(req, res, next) {
    if (!process.env.JWT_SECRET) {
        return res.status(500).json({ message: "Server configuration error." });
    }
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; 
    if (token == null) return res.status(401).json({ message: "Access denied. No token provided." });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: "Invalid token." });
        req.user = user; 
        next();
    });
}

// --- HELPER FUNCTIONS ---

// Calculate distance between two points (Haversine-like approximation for small distances)
function getDistance(lat1, lon1, lat2, lon2) {
    return Math.sqrt(Math.pow(lat1 - lat2, 2) + Math.pow(lon1 - lon2, 2));
}

// FIX: New helper to find the closest graph node to a user's coordinate
function getNearestNode(lat, lon, nodes) {
    let closest = null;
    let minDst = Infinity;
    nodes.forEach(node => {
        const dist = getDistance(lat, lon, node.latitude, node.longitude);
        if (dist < minDst) {
            minDst = dist;
            closest = node;
        }
    });
    return closest;
}

// --- Auth Routes ---
app.post('/api/register', async (req, res) => {
    const { name, email, phone_number, password } = req.body;
    if (!name || !email || !password) {
        return res.status(400).json({ message: "Name, email, and password are required." });
    }
    try {
        const password_hash = await bcrypt.hash(password, 10);

        const { data, error } = await supabase
            .from('users')
            .insert([{ name, email, phone_number, password_hash }])
            .select();

        if (error) throw error;

        res.status(201).json({ 
            message: "User registered successfully!", 
            user_id: data[0].user_id 
        });

    } catch (error) {
        if (error.code === '23505') { // Postgres code for unique violation
            return res.status(409).json({ message: "Email or phone number is already registered." });
        }
        res.status(500).json({ message: "Failed to register user due to a server error." });
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Required fields missing." });

    try {
        const { data: users, error } = await supabase
            .from('users')
            .select('user_id, password_hash')
            .eq('email', email);

        if (error || !users.length) return res.status(401).json({ message: "Invalid credentials." });

        const user = users[0];
        const passwordMatch = await bcrypt.compare(password, user.password_hash);
        if (!passwordMatch) return res.status(401).json({ message: "Invalid credentials." });

        const token = jwt.sign(
            { user_id: user.user_id, email: email },
            process.env.JWT_SECRET,
            { expiresIn: '1d' }
        );
        res.status(200).json({ message: "Login successful!", user_id: user.user_id, token });
    } catch (error) {
        res.status(500).json({ message: "Login failed error." });
    }
});

// --- Trusted Contacts ---
app.post('/api/contacts', authenticateToken, async (req, res) => {
    const user_id = req.user.user_id; 
    const { contact_name, contact_phone, relationship_type } = req.body;

    try {
        const { count, error: countErr } = await supabase
            .from('trusted_contacts')
            .select('*', { count: 'exact', head: true })
            .eq('user_id', user_id);

        if (count >= 5) return res.status(400).json({ message: "Limit reached (Max 5)." });

        const { data, error } = await supabase
            .from('trusted_contacts')
            .insert([{ user_id, contact_name, contact_phone, relationship_type }])
            .select();

        if (error) throw error;
        res.status(201).json({ message: "Contact added.", contact_id: data[0].contact_id });
    } catch (error) {
        res.status(500).json({ message: "Failed to add contact." });
    }
});

app.get('/api/contacts', authenticateToken, async (req, res) => {
    const { data, error } = await supabase
        .from('trusted_contacts')
        .select('contact_id, contact_name, contact_phone, relationship_type')
        .eq('user_id', req.user.user_id);

    if (error) return res.status(500).json({ message: "Retrieve error." });
    res.status(200).json(data);
});

app.put('/api/contacts/:contactId', authenticateToken, async (req, res) => {
    const { contact_name, contact_phone, relationship_type } = req.body;
    try {
        const { data, error } = await supabase
            .from('trusted_contacts')
            .update({ contact_name, contact_phone, relationship_type })
            .eq('contact_id', req.params.contactId)
            .eq('user_id', req.user.user_id)
            .select();

        if (error || !data.length) return res.status(404).json({ message: "Not found." });
        res.status(200).json({ message: "Updated." });
    } catch (error) {
        res.status(500).json({ message: "Update failed." });
    }
});

app.delete('/api/contacts/:contactId', authenticateToken, async (req, res) => {
    const { error } = await supabase
        .from('trusted_contacts')
        .delete()
        .eq('contact_id', req.params.contactId)
        .eq('user_id', req.user.user_id);

    if (error) return res.status(500).json({ message: "Delete failed." });
    res.status(200).json({ message: "Deleted successfully." });
});

// --- SOS Panic Routes ---
app.post('/api/location', authenticateToken, async (req, res) => {
    const { latitude, longitude } = req.body;
    try {
        const { error } = await supabase
            .from('location_history')
            .insert([{ user_id: req.user.user_id, latitude, longitude }]);

        if (error) throw error;
        res.status(201).json({ message: "Location updated." });
    } catch (error) {
        res.status(500).json({ message: "Update failed." });
    }
});

app.post('/api/panic', authenticateToken, async (req, res) => {
    try {
        const { data: loc, error: locErr } = await supabase
            .from('location_history')
            .select('latitude, longitude')
            .eq('user_id', req.user.user_id)
            .order('updated_at', { ascending: false })
            .limit(1);

        if (!loc || loc.length === 0) return res.status(404).json({ message: "Enable GPS first." });

        const { latitude, longitude } = loc[0];
        const { data: alert, error: alertErr } = await supabase
            .from('panic_alerts')
            .insert([{ user_id: req.user.user_id, latitude, longitude, status: 'active' }])
            .select();

        const { data: contacts } = await supabase
            .from('trusted_contacts')
            .select('contact_name, contact_phone')
            .eq('user_id', req.user.user_id);

        // FIX: Corrected URL formatting
        const mapsLink = `https://www.google.com/maps?q=${latitude},${longitude}`;

        res.status(201).json({
            message: "SOS Alert triggered successfully.",
            alert_id: alert[0].id,
            google_maps_link: mapsLink,
            notified_contacts: contacts
        });
    } catch (error) {
        res.status(500).json({ message: "SOS Error." });
    }
});

app.post('/api/panic/resolve', authenticateToken, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('panic_alerts')
            .update({ status: 'resolved' })
            .eq('user_id', req.user.user_id)
            .eq('status', 'active')
            .select();

        if (!data || data.length === 0) return res.status(404).json({ message: "No active alert." });
        res.json({ message: "Status updated: User is safe." });
    } catch (error) {
        res.status(500).json({ message: "Resolve failed." });
    }
});

// --- Legal AI Chat ---
app.post('/api/chat', authenticateToken, async (req, res) => {
    const { question } = req.body;
    try {
        const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" }); 
        const prompt = `Legal Assistant for 'Raksha'. Question: "${question}"`;
        const result = await model.generateContent(prompt);
        res.json({ answer: result.response.text() });
    } catch (error) {
        res.status(500).json({ message: "AI database connection error." });
    }
});

// --- Map & Routing ---
app.get('/api/map-geojson', async (req, res) => {
    try {
        const { data: zones } = await supabase.from('safety_zones').select('*');
        const { data: police } = await supabase.from('police_stations').select('*');
        
        const features = [
            ...zones.map(z => ({ 
                type: "Feature", 
                geometry: { type: "Point", coordinates: [z.longitude, z.latitude] }, 
                properties: { weight: z.weight, color: z.weight > 3 ? "red" : "green", name: z.name } 
            })),
            ...police.map(p => ({ 
                type: "Feature", 
                geometry: { type: "Point", coordinates: [p.longitude, p.latitude] }, 
                properties: { type: 'police', name: p.name } 
            }))
        ];
        res.json({ type: "FeatureCollection", features });
    } catch (err) { res.status(500).send(err); }
});

// FIX: Completely replaced with coordinate-based routing
app.post('/api/generate-safe-route', authenticateToken, async (req, res) => {
    const { startLat, startLon, endLat, endLon } = req.body; 
    
    try {
        const { data: zones } = await supabase.from('safety_zones').select('*');
        if(!zones || zones.length === 0) return res.status(404).json({message: "No safety zones data"});

        // 1. Find nearest nodes to user's clicked coordinates
        const startNode = getNearestNode(startLat, startLon, zones);
        const endNode = getNearestNode(endLat, endLon, zones);

        if (!startNode || !endNode) return res.status(400).json({ message: "No safety zones nearby." });

        let graph = createGraph();
        
        // 2. Build Graph
        zones.forEach(z => {
            graph.addNode(z.id, { id: z.id, lat: z.latitude, lon: z.longitude, weight: z.weight });
            zones.forEach(otherZ => {
                if (z.id !== otherZ.id) {
                    const dist = getDistance(z.latitude, z.longitude, otherZ.latitude, otherZ.longitude);
                    if (dist < 0.01) { // ~1km connection radius
                        graph.addLink(z.id, otherZ.id, { weight: otherZ.weight });
                    }
                }
            });
        });

        // 3. A* Pathfinding with Heuristic
        // NOTE: Updated 'path' to 'ngraphPath' to fix variable collision
        const pathFinder = ngraphPath.aStar(graph, {
            distance(from, to, link) { return link.data.weight; },
            heuristic(from, to) { return getDistance(from.data.lat, from.data.lon, to.data.lat, to.data.lon); }
        });

        const foundPath = pathFinder.find(startNode.id, endNode.id);
        
        if (foundPath && foundPath.length > 0) {
            // Return lat/lon array for drawing
            res.json({ path: foundPath.map(n => ({ lat: n.data.lat, lon: n.data.lon })).reverse() });
        } else {
            res.status(404).json({ message: "No safe path found between these points." });
        }
    } catch (err) { 
        console.error(err);
        res.status(500).send("Internal Server Error during routing."); 
    }
});

app.get('/api/emergency-contacts', async (req, res) => {
    const { data, error } = await supabase.from('emergency_contacts').select('*');
    if (error) return res.status(500).json({ message: "Load failed." });
    res.status(200).json(data);
});

// Audio Chunk Upload API
app.post('/api/panic/audio', authenticateToken, upload.single('audio'), async (req, res) => {
    try {
        const user_id = req.user.user_id;
        const audioFile = req.file;

        if (!audioFile) return res.status(400).json({ message: "No audio file received." });

        const fileName = `panic_${user_id}_${Date.now()}.webm`;

        const { data, error } = await supabase.storage
            .from('audio-recordings')
            .upload(fileName, audioFile.buffer, {
                contentType: 'audio/webm',
                upsert: false
            });

        if (error) throw error;

        const { data: urlData } = supabase.storage
            .from('audio-recordings')
            .getPublicUrl(fileName);

        res.status(201).json({ 
            message: "Audio chunk saved.", 
            url: urlData.publicUrl 
        });

    } catch (error) {
        console.error("Audio Upload Error:", error);
        res.status(500).json({ message: "Failed to upload audio." });
    }
});

// 3. Listen on the environment port
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
