# SecureAgent Website

The official landing page for SecureAgent - the open-source security scanner for AI agents.

## Tech Stack

- **Framework**: [Astro](https://astro.build/) v4.x
- **Styling**: [Tailwind CSS](https://tailwindcss.com/) v3.x
- **Deployment**: [Vercel](https://vercel.com/)

## Development

### Prerequisites

- Node.js 18+
- npm or pnpm

### Getting Started

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview
```

## Project Structure

```
website/
├── public/              # Static assets
│   ├── favicon.svg      # Site favicon
│   └── og-image.svg     # Open Graph image
├── src/
│   ├── components/      # Astro components
│   │   ├── Hero.astro
│   │   ├── Terminal.astro
│   │   ├── Features.astro
│   │   ├── EmailCapture.astro
│   │   └── Footer.astro
│   ├── layouts/         # Page layouts
│   │   └── Layout.astro
│   ├── pages/           # File-based routing
│   │   └── index.astro
│   └── styles/          # Global styles
│       └── global.css
├── astro.config.mjs     # Astro configuration
├── tailwind.config.mjs  # Tailwind configuration
├── tsconfig.json        # TypeScript configuration
└── vercel.json          # Vercel deployment config
```

## Deployment

The site is configured for deployment on Vercel:

1. Connect your GitHub repository to Vercel
2. Vercel will auto-detect Astro and configure the build
3. The `vercel.json` file provides additional configuration

### Environment Variables

For the email capture form, you'll need to set up a form handler (e.g., Formspree, ConvertKit):

```env
# Optional: Replace the form action in EmailCapture.astro
FORM_ENDPOINT=https://your-form-handler.com/endpoint
```

## SEO

The site includes:
- Meta tags (title, description, keywords)
- Open Graph tags for social sharing
- Twitter Card tags
- JSON-LD structured data
- Canonical URLs
- Favicon and touch icons

## License

MIT License - See [LICENSE](../LICENSE) for details.
