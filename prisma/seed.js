const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const prisma = new PrismaClient();

async function main() {
    // ─── Admin User ───────────────────────────────────────────────
    const adminEmail = 'admin@devseas.com';
    const hashedPassword = await bcrypt.hash('Devseas@123123', 10);
    const existingAdmin = await prisma.user.findUnique({ where: { email: adminEmail } });
    
    if (!existingAdmin) {
        const user = await prisma.user.create({
            data: { name: 'Admin User', email: adminEmail, password: hashedPassword, isAdmin: true }
        });
        console.log(`✅ Created admin: ${user.email} / new password`);
    } else {
        await prisma.user.update({
            where: { email: adminEmail },
            data: { password: hashedPassword }
        });
        console.log('ℹ️  Admin user already exists. Password updated to new password.');
    }

    // ─── Categories ───────────────────────────────────────────────
    const categories = [
        { name: 'Pharmaceutical Excipients', slug: 'pharmaceutical-excipients', description: 'High-purity excipients for pharma formulations' },
        { name: 'Industrial Chemicals',       slug: 'industrial-chemicals',       description: 'Chemicals for industrial manufacturing processes' },
        { name: 'Food Grade',                 slug: 'food-grade',                 description: 'Food-grade ingredients and additives' },
        { name: 'Cosmetics',                  slug: 'cosmetics',                  description: 'Cosmetic-grade ingredients for personal care' },
        { name: 'Agro Chemicals',             slug: 'agro-chemicals',             description: 'Agrochemical inputs for agriculture' },
        { name: 'Solvents',                   slug: 'solvents',                   description: 'High-purity solvents for processing' },
    ];

    for (const cat of categories) {
        const existing = await prisma.category.findUnique({ where: { slug: cat.slug } });
        if (!existing) {
            await prisma.category.create({ data: cat });
            console.log(`✅ Category: ${cat.name}`);
        } else {
            console.log(`ℹ️  Category exists: ${cat.name}`);
        }
    }

    // ─── Sample Products ──────────────────────────────────────────
    const pharmacat = await prisma.category.findUnique({ where: { slug: 'pharmaceutical-excipients' } });
    const indcat    = await prisma.category.findUnique({ where: { slug: 'industrial-chemicals' } });

    console.log('Category IDs:', { pharmacat: pharmacat?.id, indcat: indcat?.id });

    if (!pharmacat || !indcat) {
        console.error('❌ Essential categories not found. Seed failed.');
        return;
    }

    const products = [
        { name: 'Dried Aluminium Hydroxide',  slug: 'dried-aluminium-hydroxide-001',  casNumber: '21645-51-2', formula: 'Al(OH)3',   description: 'High purity aluminium hydroxide for antacid formulations', categoryId: pharmacat.id, grade: 'IP/BP/USP' },
        { name: 'Magnesium Hydroxide',         slug: 'magnesium-hydroxide-001',        casNumber: '1309-42-8',  formula: 'Mg(OH)2',   description: 'Pharmaceutical grade magnesium hydroxide',                categoryId: pharmacat.id, grade: 'IP/BP/USP' },
        { name: 'Sodium Chloride',             slug: 'sodium-chloride-001',            casNumber: '7647-14-5',  formula: 'NaCl',      description: 'Food and pharma grade sodium chloride',                   categoryId: pharmacat.id, grade: 'IP/BP/USP/Food' },
        { name: 'Isopropyl Alcohol (IPA)',     slug: 'isopropyl-alcohol-001',          casNumber: '67-63-0',    formula: 'C3H8O',     description: 'High-purity IPA for industrial and pharma use',           categoryId: indcat.id,    grade: 'Tech Grade' },
        { name: 'Calcium Carbonate',           slug: 'calcium-carbonate-001',          casNumber: '471-34-1',   formula: 'CaCO3',     description: 'Pharmaceutical and food grade calcium carbonate',         categoryId: pharmacat.id, grade: 'IP/BP/USP' },
    ];

    for (const prod of products) {
        try {
            const existing = await prisma.product.findUnique({ where: { slug: prod.slug } });
            if (!existing) {
                await prisma.product.create({ data: prod });
                console.log(`✅ Product: ${prod.name}`);
            } else {
                console.log(`ℹ️  Product exists: ${prod.name}`);
            }
        } catch (err) {
            console.error(`❌ Failed to seed product ${prod.name}:`, err.message);
        }
    }

    // ─── Catalogues ───────────────────────────────────────────────
    const existingCat = await prisma.catalogue.findMany({ where: { fileName: 'Catloge1.pdf' } });
    if (existingCat.length === 0) {
        await prisma.catalogue.create({
            data: {
                name: 'Main Catalogue',
                fileName: 'Catloge1.pdf',
                fileUrl: 'Catloge1.pdf'
            }
        });
        console.log('✅ Standard Catalogue Seeded');
    }
}

main()
    .catch((e) => { console.error('❌ Seed script error:', e); process.exit(1); })
    .finally(async () => { await prisma.$disconnect(); });
