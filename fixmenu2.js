const fs = require('fs');
const path = require('path');
const dir = 'public';
const files = fs.readdirSync(dir).filter(f => f.endsWith('.html') && !f.startsWith('admin-'));

files.forEach(f => {
    let p = path.join(dir, f);
    let html = fs.readFileSync(p, 'utf8');

    // Replace the dropdown menu under Products
    // Since it can be tricky to find the exact string, let's use a regex that looks for the Products link and the immediate dropdown-menu after it.

    const regex = /(<a href="products\.html"[^>]*>Products(?:\s*<i[^>]*><\/i>)?<\/a>\s*<div class="dropdown-menu">).*?(<\/div>)/s;

    // Also, some files might have nested dropdown menus, so let's be more specific
    // Or just look for the block containing 'Antacids & Laxatives'
    const blockRegex = /<div class="dropdown-menu[^"]*">\s*<a href="products\.html\?category=all"[^>]*>All Products<\/a>\s*<a href="products\.html\?category=antacids".*?<\/div>/s;

    if (blockRegex.test(html)) {
        html = html.replace(blockRegex, '<div class="dropdown-menu dropdown-categories-dynamic">\n                        <a href="products.html?category=all" class="dropdown-item">All Products</a>\n                    </div>');
        fs.writeFileSync(p, html);
        console.log('Fixed menu block in ' + f);
    } else {
        // specifically for index.html if it didn't match
        const manualIndex = html.indexOf('<a href="products.html?category=antacids"');
        if (manualIndex !== -1) {
            const startDiv = html.lastIndexOf('<div', manualIndex);
            const endDiv = html.indexOf('</div>', manualIndex);
            if (startDiv !== -1 && endDiv !== -1) {
                const replacement = '<div class="dropdown-menu dropdown-categories-dynamic">\n                        <a href="products.html?category=all" class="dropdown-item">All Products</a>\n                    </div>';
                html = html.substring(0, startDiv) + replacement + html.substring(endDiv + 6);
                fs.writeFileSync(p, html);
                console.log('Manually fixed menu in ' + f);
            }
        }
    }
});
