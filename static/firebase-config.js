// static/firebase-config.js
import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js";
import { getAuth, GoogleAuthProvider } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js";

// ВСТАВЬ СВОИ ДАННЫЕ из Firebase Console -> Project settings -> General -> Your apps (Web)
const firebaseConfig = {
    apiKey: "AIzaSyBfrX_sA_n7Pi4YECbqkpOmuJ3e8yn_tzM",
    authDomain: "psd-clone.firebaseapp.com",
    projectId: "psd-clone",
    appId: "1:689189900622:web:169e6521ce151c3006ce1f",
};

export const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const googleProvider = new GoogleAuthProvider();
