"use client";

import Link from "next/link";
import Image from "next/image";
import { usePathname } from "next/navigation";
import { BarChart3, BookOpenCheck, FileSearch, History, LibraryBig, Menu, Moon, Plus, Settings, ShieldCheck, Sun, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";

const navigation = [
  { href: "/", label: "Dashboard", icon: BarChart3 },
  { href: "/assessments/new", label: "Generate a report", icon: Plus },
  { href: "/assessments", label: "Assessment history", icon: History },
  { href: "/directory", label: "MCP directory", icon: LibraryBig },
  { href: "/rules", label: "Rule explorer", icon: BookOpenCheck },
  { href: "/reports", label: "Reports", icon: FileSearch },
  { href: "/settings", label: "Settings", icon: Settings },
];

export function AppShell({ children }: { children: React.ReactNode }) {
  const path = usePathname();
  const [dark, setDark] = useState(false);
  const [navigationOpen, setNavigationOpen] = useState(false);
  const menuButton = useRef<HTMLButtonElement>(null);
  const closeButton = useRef<HTMLButtonElement>(null);
  useEffect(() => { const active = localStorage.getItem("observatory-theme") === "dark"; setDark(active); document.documentElement.classList.toggle("dark", active); }, []);
  useEffect(() => { setNavigationOpen(false); }, [path]);
  useEffect(() => {
    if (!navigationOpen) return;
    const previousOverflow = document.body.style.overflow;
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setNavigationOpen(false);
        menuButton.current?.focus();
      }
    };
    document.body.style.overflow = "hidden";
    document.addEventListener("keydown", handleKeyDown);
    closeButton.current?.focus();
    return () => {
      document.body.style.overflow = previousOverflow;
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [navigationOpen]);
  const toggle = () => { const next=!dark; setDark(next); document.documentElement.classList.toggle("dark",next); localStorage.setItem("observatory-theme",next?"dark":"light"); };
  const closeNavigation = () => {
    setNavigationOpen(false);
    requestAnimationFrame(() => menuButton.current?.focus());
  };
  return <div className="app-shell">
    <a className="skip-link" href="#main-content">Skip to main content</a>
    {navigationOpen && <>
      <button type="button" className="navigation-scrim" aria-label="Close navigation" onClick={closeNavigation}/>
      <aside className="sidebar" id="primary-navigation" aria-label="Primary navigation">
        <div className="sidebar-header">
          <Link href="/" className="brand" onClick={closeNavigation}><Image src="/logo.png" alt="agntid.ai" width={24} height={24} className="brand-logo light-logo" priority/><Image src="/logo-darkmode.png" alt="" aria-hidden="true" width={24} height={24} className="brand-logo dark-logo"/><span className="brand-copy"><strong>Free MCP Report</strong><span>Powered by AgntID Observatory</span></span></Link>
          <button ref={closeButton} type="button" className="button icon-button sidebar-close" onClick={closeNavigation} aria-label="Close navigation"><X size={17}/></button>
        </div>
        <div className="nav-group-label">Assessment</div>
        <nav aria-label="Assessment navigation">{navigation.slice(0,3).map(item=><NavItem key={item.href} item={item} path={path} onNavigate={closeNavigation}/>)}</nav>
        <div className="nav-group-label">Intelligence</div>
        <nav aria-label="Intelligence navigation">{navigation.slice(3,6).map(item=><NavItem key={item.href} item={item} path={path} onNavigate={closeNavigation}/>)}</nav>
        <div className="nav-group-label">Workspace</div>
        <nav aria-label="Workspace navigation">{navigation.slice(6).map(item=><NavItem key={item.href} item={item} path={path} onNavigate={closeNavigation}/>)}</nav>
        <div className="sidebar-footer"><div className="sidebar-footer-title"><ShieldCheck size={14}/>Metadata-only assessment</div><p>Reviews advertised capabilities and security signals without executing tools.</p><span className="sidebar-footer-status"><ShieldCheck size={11}/>Zero MCP tool execution</span></div>
      </aside>
    </>}
    <div className="main-column">
      <header className="topbar">
        <div className="topbar-leading">
          <button ref={menuButton} type="button" className="button icon-button navigation-trigger" onClick={()=>setNavigationOpen(true)} aria-label="Open navigation" aria-expanded={navigationOpen} aria-controls="primary-navigation"><Menu size={17}/></button>
          <Link href="/" className="topbar-brand" aria-label="Free MCP Report home"><Image src="/logo.png" alt="" aria-hidden="true" width={22} height={22} className="brand-logo light-logo" priority/><Image src="/logo-darkmode.png" alt="" aria-hidden="true" width={22} height={22} className="brand-logo dark-logo"/><strong>Free MCP Report</strong></Link>
          <div className="topbar-title"><span>Powered by AgntID Observatory</span></div>
        </div>
        <button className="button icon-button" onClick={toggle} aria-label={`Switch to ${dark?"light":"dark"} theme`} title={`Switch to ${dark?"light":"dark"} theme`}>{dark?<Sun size={16}/>:<Moon size={16}/>}</button>
      </header>
      <main className="content" id="main-content">{children}</main>
    </div>
  </div>;
}

function isNavActive(href: string, path: string) {
  if (href === "/") return path === "/";
  if (href === "/assessments/new") return path === href;
  if (href === "/assessments") {
    return path === href || (path.startsWith(`${href}/`) && path !== "/assessments/new");
  }
  return path.startsWith(href);
}

function NavItem({item,path,onNavigate}:{item:(typeof navigation)[number];path:string;onNavigate?:()=>void}) {
  const active = isNavActive(item.href, path);
  const Icon = item.icon;
  return <Link className={`nav-link ${active?"active":""}`} aria-current={active?"page":undefined} href={item.href} onClick={onNavigate}><Icon size={15}/>{item.label}</Link>;
}
