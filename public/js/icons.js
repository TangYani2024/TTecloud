const ICONS = {
  folder: <svg class=ui-svg-icon viewBox=0 0 24 24 fill=none>
    <path d=M4 20h16a1 1 0 0 0 1-1V7a1 1 0 0 0-1-1h-7l-2-3H5a1 1 0 0 0-1 1v15a1 1 0 0 0 1 1Z fill=#F59E0B fill-opacity=0.26 stroke=#F59E0B stroke-width=1.2 stroke-linecap=round stroke-linejoin=round/>
    <path d=M3 8h18v11a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V8Z fill=#FFD23F fill-opacity=0.32 stroke=#F59E0B stroke-width=1.1 stroke-linecap=round stroke-linejoin=round/>
    <path d=M3 8h18 stroke=#FFE57F stroke-width=0.9 stroke-opacity=0.8 stroke-linecap=round/>
  </svg>,

  folderLocked: <svg class=ui-svg-icon viewBox=0 0 24 24 fill=none>
    <path d=M4 20h16a1 1 0 0 0 1-1V7a1 1 0 0 0-1-1h-7l-2-3H5a1 1 0 0 0-1 1v15a1 1 0 0 0 1 1Z fill=#C780E8 fill-opacity=0.15 stroke=#C780E8 stroke-width=1.2 stroke-linecap=round stroke-linejoin=round/>
    <path d=M3 8h18v11a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V8Z fill=#E0A9F5 fill-opacity=0.18 stroke=#E0A9F5 stroke-width=1.1 stroke-linecap=round stroke-linejoin=round/>
    <rect x=9 y=13 width=6 height=5 rx=1 fill=#2C1B4E fill-opacity=0.5 stroke=#A070D0 stroke-width=1 stroke-linecap=round/>
    <path d=M12 13v-1.5a1.5 1.5 0 0 0-3 0V13 stroke=#A070D0 stroke-width=1.1 fill=none stroke-linecap=round/>
    <circle cx=12 cy=15.5 r=0.8 fill=#FFE499 fill-opacity=0.8 stroke=none/>
  </svg>,

  archive: <svg class=ui-svg-icon viewBox=0 0 24 24 fill=none>
    <path d=M4 20h16a1 1 0 0 0 1-1V7a1 1 0 0 0-1-1h-7l-2-3H5a1 1 0 0 0-1 1v15a1 1 0 0 0 1 1Z fill=#4ECDC4 fill-opacity=0.15 stroke=#4ECDC4 stroke-width=1.2 stroke-linecap=round stroke-linejoin=round/>
    <path d=M3 8h18v11a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V8Z fill=#A8E6E0 fill-opacity=0.18 stroke=#A8E6E0 stroke-width=1.1 stroke-linecap=round stroke-linejoin=round/>
    <path d=M12 6v12 stroke=#4ECDC4 stroke-width=1.4 stroke-dasharray=1.8 2.2 stroke-opacity=0.7 stroke-linecap=round/>
    <rect x=11 y=9 width=2 height=2 rx=0.5 fill=#4ECDC4 fill-opacity=0.5 stroke=none/>
    <rect x=11 y=13 width=2 height=2 rx=0.5 fill=#4ECDC4 fill-opacity=0.5 stroke=none/>
  </svg>,

  video: <svg class=ui-svg-icon viewBox=0 0 24 24 fill=none>
    <rect x=2 y=6 width=20 height=12 rx=2.5 fill=#1E3A5F fill-opacity=0.35 stroke=#4A9EFF stroke-width=1.2 stroke-linecap=round/>
    <rect x=5 y=9 width=3 height=6 rx=0.8 fill=#4A9EFF fill-opacity=0.2 stroke=none/>
    <rect x=16 y=9 width=3 height=6 rx=0.8 fill=#4A9EFF fill-opacity=0.2 stroke=none/>
    <circle cx=12 cy=12 r=2.8 fill=#FF6B9D fill-opacity=0.35 stroke=#FF6B9D stroke-width=1 stroke-linecap=round/>
    <path d=M11 10.8v2.4l2-1.2-2-1.2Z fill=#FFB3D1 fill-opacity=0.7 stroke=none/>
  </svg>,

  audio: <svg class=ui-svg-icon viewBox=0 0 24 24 fill=none>
    <circle cx=8 cy=17 r=3.2 fill=#C445B5 fill-opacity=0.2 stroke=#C445B5 stroke-width=1.2 stroke-linecap=round/>
    <circle cx=18 cy=15 r=3.2 fill=#C445B5 fill-opacity=0.2 stroke=#C445B5 stroke-width=1.2 stroke-linecap=round/>
    <path d=M11 17V6l9-2v11 stroke=#C445B5 stroke-width=1.3 fill=none stroke-opacity=0.7 stroke-linecap=round/>
    <path d=M11 11l9-2 stroke=#C445B5 stroke-width=1.1 fill=none stroke-opacity=0.5 stroke-linecap=round/>
    <circle cx=8 cy=17 r=1 fill=#FFE066 fill-opacity=0.6 stroke=none/>
    <circle cx=18 cy=15 r=1 fill=#FFE066 fill-opacity=0.6 stroke=none/>
  </svg>,

  document: <svg class=ui-svg-icon viewBox=0 0 24 24 fill=none>
    <path d=M6 3h8l5 5v13a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1Z fill=#E0ECFF fill-opacity=0.15 stroke=#8AB8E8 stroke-width=1.2 stroke-linecap=round stroke-linejoin=round/>
    <path d=M14 3v5h5 fill=none stroke=#8AB8E8 stroke-width=1.2 stroke-opacity=0.7 stroke-linecap=round stroke-linejoin=round/>
    <path d=M9 13h6M9 17h4 stroke=#8AB8E8 stroke-width=1.1 stroke-linecap=round stroke-opacity=0.5/>
  </svg>,

  code: <svg class=ui-svg-icon viewBox=0 0 24 24 fill=none>
    <path d=M6 3h8l5 5v13a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1Z fill=#1E2A3A fill-opacity=0.4 stroke=#61DAFB stroke-width=1.2 stroke-linecap=round stroke-linejoin=round/>
    <path d=M14 3v5h5 fill=none stroke=#61DAFB stroke-width=1.2 stroke-opacity=0.6 stroke-linecap=round stroke-linejoin=round/>
    <path d=M10.5 13.5L8.5 16l2 2.5 stroke=#61DAFB stroke-width=1.3 fill=none stroke-linecap=round stroke-linejoin=round stroke-opacity=0.9/>
    <path d=M13.5 13.5l2 2.5-2 2.5 stroke=#61DAFB stroke-width=1.3 fill=none stroke-linecap=round stroke-linejoin=round stroke-opacity=0.9/>
    <circle cx=12 cy=9 r=1 fill=#F0DB4F fill-opacity=0.6 stroke=none/>
  </svg>
};
