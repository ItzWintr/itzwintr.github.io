const translations = {
    en: {
        // Navbar
        nav_certs: "Certifications",
        nav_tools: "Tools",
        nav_trajectory: "Trajectory",
        nav_socials: "Socials",
        nav_contact: "Contact",
        
        // Hero
        hero_tag: "Active: CTF & Bug Bounties",
        hero_desc: "Cybersecurity Expert. Red Team eJPTv2 & Blue Team Google Certified. Specialized in offensive security and defensive intelligence.",
        hero_btn1: "Direct Link",
        hero_btn2: "View Arsenal",

        // Certifications
        cert_pretitle: "Certifications",
        cert_title: "Core Accreditations",
        cert_ejpt_desc: "Junior Penetration Tester certification focused on practical penetration testing methodologies and techniques. Red Team tools and OSINT techniques.",
        cert_google_desc: "Comprehensive professional training in threat detection, response, and security operations. SIEM operating and database operations.",
        cert_cisco_desc: "Strategic network architecture defense and enterprise-level infrastructure security, as well as hardening techniques and international regulations.",

        // Technical Arsenal
        tools_pretitle: "Technical Arsenal",
        tools_title: "Precision Grade Tooling",
        tools_nmap_desc: "Network Vulnerability Scanner",
        tools_wireshark_desc: "Network Assessment",
        tools_gobuster_desc: "Directory Fuzzing",
        tools_hashcat_desc: "Hash Cracking",
        tools_john_desc: "Hash Cracking/Bruteforce",
        tools_osint_desc: "Open Source Intelligence",

        // Trajectory
        traj_pretitle: "Trajectory",
        traj_title: "Professional Evolution",
        traj_cisco_desc: "Advanced academic specialization in architectural defense systems and enterprise-grade threat management.",
        traj_ejpt_desc: "Successful mastery of offensive security methodologies, penetration testing, and ethical hacking protocols.",
        traj_sysadmin: "System Administrator & Computer Repair Technician",
        traj_sysadmin_desc: "Infrastructure maintenance, system troubleshooting, and hardware engineering across multiple hardware environments.",
        traj_grado: "Degree in Microcomputer Systems and Networks",
        traj_grado_desc: "Foundational training in networking, computing systems, and technical infrastructure management.",

        // Writeups
        writeups_title: "Machines Solved",
        writeups_disclaimer: "* Please note that all writeups are completely in English.",
        writeups_easy: "Easy",
        writeups_medium: "Medium",
        writeups_read: "Read Writeup",

        // Contact
        contact_title: "Contact Me",
        contact_desc: "Focused on building environments that are safer, more efficient, and better prepared for real-world attacks.",
        contact_btn: "Open Communications Interface"
    },
    es: {
        // Navbar
        nav_certs: "Certificaciones",
        nav_tools: "Herramientas",
        nav_trajectory: "Trayectoria",
        nav_socials: "Redes",
        nav_contact: "Contacto",
        
        // Hero
        hero_tag: "Activo: CTF & Bug Bounties",
        hero_desc: "Experto en Ciberseguridad. Red Team eJPTv2 & Blue Team Google Certified. Especializado en seguridad ofensiva e inteligencia defensiva.",
        hero_btn1: "Enlace Directo",
        hero_btn2: "Ver Arsenal",

        // Certifications
        cert_pretitle: "Certificaciones",
        cert_title: "Acreditaciones Principales",
        cert_ejpt_desc: "Certificación de Junior Penetration Tester enfocada en metodologías prácticas de test de intrusión y uso de herramientas Red Team u OSINT.",
        cert_google_desc: "Entrenamiento profesional integral en detección de amenazas, respuesta y operaciones de seguridad. Manejo de sistemas SIEM y bases de datos.",
        cert_cisco_desc: "Defensa estratégica de arquitecturas de red y seguridad de infraestructura corporativa, así como técnicas de hardening de red y regulaciones.",

        // Technical Arsenal
        tools_pretitle: "Arsenal Técnico",
        tools_title: "Herramientas Profesionales",
        tools_nmap_desc: "Escáner de Vulnerabilidades de Red",
        tools_wireshark_desc: "Evaluación de Red",
        tools_gobuster_desc: "Fuzzing de Directorios",
        tools_hashcat_desc: "Craqueo de Hashes",
        tools_john_desc: "Craqueo de Hashes / Fuerza Bruta",
        tools_osint_desc: "Inteligencia de Fuentes Abiertas",

        // Trajectory
        traj_pretitle: "Trayectoria",
        traj_title: "Evolución Profesional",
        traj_cisco_desc: "Especialización académica avanzada en sistemas de defensa arquitectónica y gestión corporativa de amenazas.",
        traj_ejpt_desc: "Dominio correcto de metodologías de seguridad ofensiva, tests de penetración y protocolos de hacking ético.",
        traj_sysadmin: "Administrador de Sistemas y Técnico en Reparación de Ordenadores",
        traj_sysadmin_desc: "Mantenimiento de infraestructuras, resolución de problemas en sistemas e ingeniería de hardware en múltiples entornos.",
        traj_grado: "Grado en Sistemas Microinformáticos y Redes",
        traj_grado_desc: "Formación inicial sólida en redes, sistemas informáticos y gestión técnica de infraestructuras.",

        // Writeups
        writeups_title: "Máquinas Resueltas",
        writeups_disclaimer: "* Ten en cuenta que todos los writeups se encuentran íntegramente en inglés.",
        writeups_easy: "Fácil",
        writeups_medium: "Medio",
        writeups_read: "Leer Writeup",

        // Contact
        contact_title: "Contacta Conmigo",
        contact_desc: "Enfocado en construir entornos más seguros, eficientes y preparados para ataques reales.",
        contact_btn: "Abrir Interfaz de Comunicaciones"
    }
};

let currentLang = localStorage.getItem('site_lang') || 'en';

function applyTranslations(lang) {
    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        if (translations[lang] && translations[lang][key]) {
            el.innerHTML = translations[lang][key]; 
        }
    });

    const toggleBtn = document.getElementById('lang-toggle');
    if (toggleBtn) {
        toggleBtn.textContent = lang === 'en' ? 'ES' : 'EN';
    }
}

function toggleLanguage() {
    currentLang = currentLang === 'en' ? 'es' : 'en';
    localStorage.setItem('site_lang', currentLang);
    applyTranslations(currentLang);
}

document.addEventListener('DOMContentLoaded', () => {
    applyTranslations(currentLang);
    const toggleBtn = document.getElementById('lang-toggle');
    if (toggleBtn) {
        toggleBtn.addEventListener('click', (e) => {
            e.preventDefault();
            toggleLanguage();
        });
    }
});
