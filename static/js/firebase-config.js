// static/js/firebase-config.js
import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js";
import { getAuth, GoogleAuthProvider } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js";
import { getFirestore } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore.js";
import { getStorage } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-storage.js";


const firebaseConfig = {
    apiKey: "AIzaSyBfrX_sA_n7Pi4YECbqkpOmuJ3e8yn_tzM",
    authDomain: "psd-clone.firebaseapp.com",
    projectId: "psd-clone",
    storageBucket: "psd-clone.firebasestorage.app",
    messagingSenderId: "689189900622",
    appId: "1:689189900622:web:169e6521ce151c3006ce1f",
    measurementId: "G-W56MPG64P7"
};

const app = initializeApp(firebaseConfig);

export const auth = getAuth(app);
export const googleProvider = new GoogleAuthProvider();
export const db = getFirestore(app);
export const storage = getStorage(app);
