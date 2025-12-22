import { auth } from "/static/js/firebase-config.js";
import {
    GoogleAuthProvider,
    signInWithPopup,
    onAuthStateChanged,
    signOut
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js";

const el = (id) => document.getElementById(id);

const btnGoogle = el("btnGoogle");
if (btnGoogle) {
    btnGoogle.onclick = async () => {
        try {
            const provider = new GoogleAuthProvider();
            await signInWithPopup(auth, provider);
            location.href = "/admin";
        } catch (e) {
            const msg = el("msg");
            if (msg) msg.textContent = e.message;
            console.error(e);
        }
    };
}

// чтобы формы (admin) получали id_token автоматически
async function fillFormsWithToken() {
    const u = auth.currentUser;
    if (!u) return;
    const token = await u.getIdToken();
    document.querySelectorAll("form.needs-token input[name='id_token']").forEach(inp => {
        inp.value = token;
    });
}

onAuthStateChanged(auth, async () => {
    await fillFormsWithToken();

    const logoutBtn = el("btnLogout");
    if (logoutBtn) {
        logoutBtn.onclick = async () => {
            await signOut(auth);
            location.href = "/";
        };
    }
});
