// static/js/shop.js
import { db } from "./firebase-config.js";
import {
    collection,
    getDocs,
    query,
    orderBy
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore.js";

async function loadShopProducts() {
    const list = document.querySelector(".products-list"); // твій контейнер на головній
    if (!list) return;

    const q = query(collection(db, "products"), orderBy("createdAt", "desc"));
    const snap = await getDocs(q);

    list.innerHTML = "";

    snap.forEach(docSnap => {
        const p = docSnap.data();

        const card = document.createElement("div");
        card.className = "product-card";
        // ...зробити верстку по твоєму дизайну, взяти ті ж поля: photo, name, price, salePrice, limited, qty тощо
        list.appendChild(card);
    });
}

loadShopProducts().catch(console.error);
