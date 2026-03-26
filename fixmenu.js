const fs = require('fs');
const path = require('path');
const dir = 'public';
const files = fs.readdirSync(dir).filter(f => f.endsWith('.html') && !f.startsWith('admin-'));

files.forEach(f => {
    let p = path.join(dir, f);
    let html = fs.readFileSync(p, 'utf8');

    // Find the products dropdown menu specifically by looking for the "Products" nav item
    const navItemStart = html.indexOf('<a href="products.html" class="active" onclick="toggleDropdown(event, this)">Products');
    const navItemStartInactive = html.indexOf('<a href="products.html" onclick="toggleDropdown(event, this)">Products');

    let target = navItemStart !== -1 ? navItemStart : navItemStartInactive;

    if (target !== -1) {
        const dropdownStart = html.indexOf('<div class="dropdown-menu">', target);

        if (dropdownStart !== -1 && (dropdownStart - target) < 200) {
            const dropdownEnd = html.indexOf('</div>', dropdownStart);

            if (dropdownEnd !== -1) {
                let newHtml = html.substring(0, dropdownStart) +
                    '<div class="dropdown-menu dropdown-categories-dynamic">' +
                    '\n                        <a href="products.html?category=all" class="dropdown-item">All Products</a>' +
                    '\n                    </div>' +
                    html.substring(dropdownEnd + 6);

                fs.writeFileSync(p, newHtml);
                console.log('Fixed menu in ' + f);
            }
        }
    }
});
