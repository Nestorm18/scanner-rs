use eframe::egui::{
    self, Align, Align2, Color32, CornerRadius, FontFamily, FontId, Layout, RichText, Sense,
    Stroke, Vec2,
};
use rfd::FileDialog;
use scanner_rs::cli::Verbosity;
use scanner_rs::output::{render_csv, render_html, render_text, render_xml};
use scanner_rs::platform::{local_networks, LocalNetwork};
use scanner_rs::probes::ProbeDatabase;
use scanner_rs::scanner::{scan_progressive, HostResult, ScanEvent, ScanOptions};
use scanner_rs::source::parse_source;
use scanner_rs::targets::Ipv4Range;
use scanner_rs::vendor;
use std::cmp::Ordering as CmpOrdering;
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

const ACCENT: Color32 = Color32::from_rgb(37, 99, 235);
const ACCENT_SOFT: Color32 = Color32::from_rgb(232, 240, 254);
const SUCCESS: Color32 = Color32::from_rgb(22, 163, 74);
const DANGER: Color32 = Color32::from_rgb(220, 38, 38);
const BACKGROUND: Color32 = Color32::from_rgb(248, 249, 251);
const SURFACE: Color32 = Color32::WHITE;
const BORDER: Color32 = Color32::from_rgb(226, 230, 236);
const TEXT: Color32 = Color32::from_rgb(17, 24, 39);
const MUTED: Color32 = Color32::from_rgb(107, 114, 128);
const ROW_HEIGHT: f32 = 34.0;
const SEMIBOLD: &str = "semibold";

pub fn run() -> eframe::Result<()> {
    let icon = egui::IconData {
        rgba: scanner_rs::icon::rgba(64),
        width: 64,
        height: 64,
    };
    let size = Vec2::new(1040.0, 680.0);
    let mut viewport = egui::ViewportBuilder::default()
        .with_title("scanner-rs")
        .with_icon(icon)
        .with_inner_size(size)
        .with_min_inner_size([760.0, 480.0]);
    // Center on the work area (screen minus taskbar); eframe's own centering
    // uses the whole monitor.
    let centered = match work_area() {
        Some(area) => {
            let outer = size + Vec2::new(16.0, 39.0);
            let position = area.center() - outer / 2.0;
            viewport = viewport.with_position(position.max(area.min));
            false
        }
        None => true,
    };
    let options = eframe::NativeOptions {
        viewport,
        centered,
        ..Default::default()
    };

    eframe::run_native(
        "scanner-rs",
        options,
        Box::new(|context| Ok(Box::new(ScannerApp::new(context)))),
    )
}

/// Primary monitor work area in logical points (before DPI awareness is set,
/// Windows reports scaled coordinates, which match egui points).
#[cfg(windows)]
fn work_area() -> Option<egui::Rect> {
    #[repr(C)]
    struct Rect {
        left: i32,
        top: i32,
        right: i32,
        bottom: i32,
    }
    #[link(name = "user32")]
    extern "system" {
        fn SystemParametersInfoW(action: u32, param: u32, data: *mut Rect, flags: u32) -> i32;
    }
    const SPI_GETWORKAREA: u32 = 0x0030;
    let mut rect = Rect {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };
    let ok = unsafe { SystemParametersInfoW(SPI_GETWORKAREA, 0, &mut rect, 0) } != 0;
    (ok && rect.right > rect.left && rect.bottom > rect.top).then(|| {
        egui::Rect::from_min_max(
            egui::pos2(rect.left as f32, rect.top as f32),
            egui::pos2(rect.right as f32, rect.bottom as f32),
        )
    })
}

#[cfg(not(windows))]
fn work_area() -> Option<egui::Rect> {
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanDepth {
    Quick,
    Normal,
    Complete,
}

impl ScanDepth {
    const ALL: [Self; 3] = [Self::Quick, Self::Normal, Self::Complete];

    fn label(self) -> &'static str {
        match self {
            Self::Quick => "Rápido",
            Self::Normal => "Normal",
            Self::Complete => "Completo",
        }
    }

    fn hint(self) -> &'static str {
        match self {
            Self::Quick => "Solo equipos activos",
            Self::Normal => "Equipos y servicios",
            Self::Complete => "Servicios + usuarios y recursos de Windows",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Column {
    Address,
    Name,
    Vendor,
    Services,
    Mac,
}

impl Column {
    fn title(self) -> &'static str {
        match self {
            Self::Address => "IP",
            Self::Name => "Nombre",
            Self::Vendor => "Fabricante",
            Self::Services => "Servicios",
            Self::Mac => "MAC",
        }
    }

    /// `Ok(points)` for a fixed width, `Err(weight)` to share the remaining space.
    fn width(self) -> Result<f32, f32> {
        match self {
            Self::Address => Ok(140.0),
            Self::Mac => Ok(170.0),
            Self::Name => Err(0.3),
            Self::Vendor => Err(0.25),
            Self::Services => Err(0.45),
        }
    }
}

enum ScanMessage {
    Event(ScanEvent),
    Finished(Duration),
}

enum Status {
    Idle,
    Done { elapsed: Duration, cancelled: bool },
    Info(String),
    Error(String),
}

struct Row {
    host: HostResult,
    detailed: bool,
}

struct ActiveScan {
    receiver: mpsc::Receiver<ScanMessage>,
    cancel: Arc<AtomicBool>,
    started: Instant,
}

struct ScannerApp {
    target: String,
    depth: ScanDepth,
    filter: String,
    networks: Vec<LocalNetwork>,
    rows: Vec<Row>,
    sort: (Column, bool),
    show_details: bool,
    show_vendor: bool,
    selected: Option<Ipv4Addr>,
    scan: Option<ActiveScan>,
    probed: usize,
    total: usize,
    status: Status,
}

impl ScannerApp {
    fn new(context: &eframe::CreationContext<'_>) -> Self {
        setup_fonts(&context.egui_ctx);
        apply_theme(&context.egui_ctx);

        let mut networks = local_networks();
        networks.sort_by_key(|network| adapter_rank(&network.name));
        let target = networks
            .first()
            .map(range_text)
            .unwrap_or_else(|| "192.168.1.1-192.168.1.254".to_owned());

        Self {
            target,
            depth: ScanDepth::Normal,
            filter: String::new(),
            networks,
            rows: Vec::new(),
            sort: (Column::Address, true),
            show_details: true,
            show_vendor: true,
            selected: None,
            scan: None,
            probed: 0,
            total: 0,
            status: Status::Idle,
        }
    }

    fn collect_targets(&self) -> Result<Vec<Ipv4Addr>, String> {
        let input = self.target.trim().trim_matches('"');
        if input.is_empty() {
            return Err("Escribe una IP o un rango".to_owned());
        }

        let targets: Vec<Ipv4Addr> = if let Ok(range) = input.parse::<Ipv4Range>() {
            range.into_iter().collect()
        } else if Path::new(input).is_file() {
            let contents = fs::read_to_string(input)
                .map_err(|error| format!("No se pudo leer el archivo: {error}"))?;
            parse_source(&contents)
                .map_err(|error| error.to_string())?
                .into_iter()
                .flat_map(|range| range.into_iter())
                .collect()
        } else {
            return Err("IP, rango o archivo no válido".to_owned());
        };

        if targets.is_empty() {
            Err("No hay direcciones para escanear".to_owned())
        } else {
            Ok(targets)
        }
    }

    fn start_scan(&mut self) {
        let targets = match self.collect_targets() {
            Ok(targets) => targets,
            Err(error) => {
                self.status = Status::Error(error);
                return;
            }
        };

        let depth = self.depth;
        let (sender, receiver) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);

        self.rows.clear();
        self.selected = None;
        self.probed = 0;
        self.total = targets.len();
        self.status = Status::Idle;
        self.scan = Some(ActiveScan {
            receiver,
            cancel,
            started: Instant::now(),
        });

        thread::spawn(move || {
            let started = Instant::now();
            let mut options = ScanOptions {
                max_workers: thread::available_parallelism()
                    .map(|value| value.get().saturating_mul(8).clamp(32, 128))
                    .unwrap_or(64),
                collect_http_metadata: depth != ScanDepth::Quick,
                collect_windows_enrichment: depth == ScanDepth::Complete,
                ..ScanOptions::default()
            };
            if depth == ScanDepth::Quick {
                options.ports.clear();
            } else if let Ok(Some(database)) = ProbeDatabase::load_default() {
                options.probe_database = Some(Arc::new(database));
            }

            let events = sender.clone();
            scan_progressive(targets, options, worker_cancel, move |event| {
                let _ = events.send(ScanMessage::Event(event));
            });
            let _ = sender.send(ScanMessage::Finished(started.elapsed()));
        });
    }

    fn stop_scan(&mut self) {
        if let Some(scan) = self.scan.take() {
            scan.cancel.store(true, Ordering::Relaxed);
            self.status = Status::Done {
                elapsed: scan.started.elapsed(),
                cancelled: true,
            };
        }
    }

    fn poll_messages(&mut self) {
        let Some(scan) = &self.scan else {
            return;
        };
        let mut finished = None;
        let mut changed = false;
        while let Ok(message) = scan.receiver.try_recv() {
            match message {
                ScanMessage::Event(ScanEvent::Probed) => self.probed += 1,
                ScanMessage::Event(ScanEvent::Found(host)) => {
                    self.rows.push(Row {
                        host,
                        detailed: false,
                    });
                    changed = true;
                }
                ScanMessage::Event(ScanEvent::Detailed(host)) => {
                    if let Some(row) = self
                        .rows
                        .iter_mut()
                        .find(|row| row.host.address == host.address)
                    {
                        row.host = host;
                        row.detailed = true;
                        changed = true;
                    }
                }
                ScanMessage::Finished(elapsed) => finished = Some(elapsed),
            }
        }
        if changed {
            self.sort_rows();
        }
        if let Some(elapsed) = finished {
            self.scan = None;
            self.status = Status::Done {
                elapsed,
                cancelled: false,
            };
        }
    }

    fn sort_rows(&mut self) {
        let (column, ascending) = self.sort;
        self.rows.sort_by(|a, b| {
            let (a, b) = (&a.host, &b.host);
            let ordering = match column {
                Column::Address => a.address.cmp(&b.address),
                Column::Name => compare_text(a.hostname.as_deref(), b.hostname.as_deref()),
                Column::Services => a
                    .services
                    .len()
                    .cmp(&b.services.len())
                    .then_with(|| first_port(a).cmp(&first_port(b))),
                Column::Vendor => compare_text(vendor_of(a), vendor_of(b)),
                Column::Mac => compare_text(a.mac_address.as_deref(), b.mac_address.as_deref()),
            };
            let ordering = if ascending {
                ordering
            } else {
                ordering.reverse()
            };
            ordering.then_with(|| a.address.cmp(&b.address))
        });
    }

    fn set_sort(&mut self, column: Column) {
        self.sort = if self.sort.0 == column {
            (column, !self.sort.1)
        } else {
            // Services start with "most first"; the rest alphabetically.
            (column, column != Column::Services)
        };
        self.sort_rows();
    }

    fn export(&mut self) {
        let Some(path) = FileDialog::new()
            .add_filter("HTML", &["html"])
            .add_filter("CSV", &["csv"])
            .add_filter("XML", &["xml"])
            .add_filter("Texto", &["txt"])
            .set_file_name("resultados.html")
            .save_file()
        else {
            return;
        };
        let hosts: Vec<HostResult> = self.rows.iter().map(|row| row.host.clone()).collect();
        let extension = path
            .extension()
            .map(|extension| extension.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        let contents = match extension.as_str() {
            "csv" => render_csv(&hosts),
            "xml" => render_xml(&hosts),
            "txt" => render_text(&hosts, Verbosity::GroupedServices),
            _ => render_html(&hosts),
        };
        let path = if extension.is_empty() {
            path.with_extension("html")
        } else {
            path
        };
        self.status = match fs::write(&path, contents) {
            Ok(()) => Status::Info(format!("Guardado: {}", file_name(&path))),
            Err(error) => Status::Error(format!("No se pudo guardar: {error}")),
        };
    }

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        let running = self.scan.is_some();
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.spacing_mut().item_spacing.x = 8.0;

            let (label, fill) = if running {
                ("Detener", DANGER)
            } else {
                ("Escanear", ACCENT)
            };
            let button = egui::Button::new(semibold(label, 14.0).color(Color32::WHITE))
                .fill(fill)
                .min_size(Vec2::new(120.0, 36.0));
            if ui.add(button).clicked() {
                if running {
                    self.stop_scan();
                } else {
                    self.start_scan();
                }
            }

            ui.add_enabled_ui(!running, |ui| segmented(ui, &mut self.depth));
            ui.add_enabled_ui(!running, |ui| self.targets_menu(ui));

            let field = egui::TextEdit::singleline(&mut self.target)
                .hint_text("IP, rango o archivo")
                .font(FontId::proportional(15.0))
                .margin(Vec2::new(10.0, 8.0))
                .desired_width(ui.available_width());
            let response = ui.add_enabled(!running, field);
            if response.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter)) {
                self.start_scan();
            }
        });
    }

    fn targets_menu(&mut self, ui: &mut egui::Ui) {
        let response = ui
            .add(egui::Button::new(RichText::new("▾").size(16.0)).min_size(Vec2::new(36.0, 36.0)))
            .on_hover_text("Redes y archivos");
        egui::Popup::menu(&response)
            .close_behavior(egui::PopupCloseBehavior::CloseOnClick)
            .width(280.0)
            .show(|ui| {
                for network in &self.networks {
                    let range = range_text(network);
                    let selected = self.target == range;
                    let label = format!(
                        "{}   {}/{}",
                        network.name,
                        network.network(),
                        network.prefix
                    );
                    if ui.selectable_label(selected, label).clicked() {
                        self.target = range;
                    }
                }
                if !self.networks.is_empty() {
                    ui.separator();
                }
                if ui.selectable_label(false, "Abrir archivo…").clicked() {
                    if let Some(path) = FileDialog::new()
                        .add_filter("Texto", &["txt", "csv"])
                        .pick_file()
                    {
                        self.target = path.display().to_string();
                    }
                }
            });
    }

    fn status_line(&self, ui: &mut egui::Ui) {
        if let Some(scan) = &self.scan {
            ui.add(egui::Spinner::new().size(16.0).color(ACCENT));
            let found = self.rows.len();
            let detailed = self.rows.iter().filter(|row| row.detailed).count();
            let text = if self.probed < self.total {
                format!("Buscando equipos · {} / {}", self.probed, self.total)
            } else {
                format!("Analizando servicios · {detailed} / {found}")
            };
            ui.label(RichText::new(text).color(TEXT));
            ui.label(RichText::new(format_duration(scan.started.elapsed())).color(MUTED));
            return;
        }
        let (text, color) = match &self.status {
            Status::Idle => return,
            Status::Done { elapsed, cancelled } => (
                format!(
                    "{}{} {} · {}",
                    if *cancelled { "Detenido · " } else { "" },
                    self.rows.len(),
                    if self.rows.len() == 1 {
                        "equipo"
                    } else {
                        "equipos"
                    },
                    format_duration(*elapsed)
                ),
                MUTED,
            ),
            Status::Info(text) => (text.clone(), SUCCESS),
            Status::Error(text) => (text.clone(), DANGER),
        };
        ui.label(RichText::new(text).color(color));
    }

    fn results(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.set_min_height(30.0);
            self.status_line(ui);
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if !self.rows.is_empty() {
                    if ui
                        .add_enabled(self.scan.is_none(), egui::Button::new("Exportar"))
                        .clicked()
                    {
                        self.export();
                    }
                    ui.add(
                        egui::TextEdit::singleline(&mut self.filter)
                            .hint_text("Buscar")
                            .margin(Vec2::new(8.0, 5.0))
                            .desired_width(200.0),
                    );
                }
                ui.add_space(8.0);
                ui.checkbox(&mut self.show_details, "Detalles");
                if ui.checkbox(&mut self.show_vendor, "Fabricante").changed()
                    && !self.show_vendor
                    && self.sort.0 == Column::Vendor
                {
                    self.set_sort(Column::Address);
                }
            });
        });
        ui.add_space(8.0);

        if self.rows.is_empty() {
            let message = match self.status {
                _ if self.scan.is_some() => "",
                Status::Done { .. } => "No se encontraron equipos",
                _ => "Elige una red o escribe un rango y pulsa Escanear",
            };
            ui.centered_and_justified(|ui| {
                ui.label(RichText::new(message).size(16.0).color(MUTED));
            });
            return;
        }

        let filter = self.filter.trim().to_lowercase();
        let visible: Vec<usize> = self
            .rows
            .iter()
            .enumerate()
            .filter(|(_, row)| filter.is_empty() || searchable(&row.host).contains(&filter))
            .map(|(index, _)| index)
            .collect();

        egui::Frame::new()
            .fill(SURFACE)
            .stroke(Stroke::new(1.0_f32, BORDER))
            .corner_radius(CornerRadius::same(8))
            .show(ui, |ui| {
                ui.set_min_size(ui.available_size());
                let columns = self.columns(ui.available_width());
                if let Some(column) = header_row(ui, &columns, self.sort) {
                    self.set_sort(column);
                }
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show_rows(ui, ROW_HEIGHT, visible.len(), |ui, range| {
                        for &index in &visible[range] {
                            let row = &self.rows[index];
                            let selected = self.selected == Some(row.host.address);
                            if host_row(ui, &columns, row, selected).clicked() {
                                self.selected = (!selected).then_some(row.host.address);
                            }
                        }
                    });
            });
    }

    fn progress(&self) -> f32 {
        let found = self.rows.len();
        let detailed = self.rows.iter().filter(|row| row.detailed).count();
        let total = self.total + found;
        if total == 0 {
            0.0
        } else {
            (self.probed + detailed) as f32 / total as f32
        }
    }
}

impl ScannerApp {
    /// Visible columns with their widths for the given table width.
    fn columns(&self, total: f32) -> Vec<(Column, f32)> {
        let mut columns = vec![Column::Address, Column::Name];
        if self.show_vendor {
            columns.push(Column::Vendor);
        }
        columns.extend([Column::Services, Column::Mac]);

        let fixed: f32 = columns.iter().filter_map(|c| c.width().ok()).sum();
        let weights: f32 = columns.iter().filter_map(|c| c.width().err()).sum();
        let rest = (total - fixed).max(240.0);
        columns
            .into_iter()
            .map(|column| {
                let width = match column.width() {
                    Ok(width) => width,
                    Err(weight) => rest * weight / weights,
                };
                (column, width)
            })
            .collect()
    }
}

impl eframe::App for ScannerApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll_messages();
        if self.scan.is_some() {
            ui.ctx().request_repaint_after(Duration::from_millis(30));
        }

        egui::Panel::top("toolbar")
            .frame(
                egui::Frame::new()
                    .fill(SURFACE)
                    .inner_margin(egui::Margin::symmetric(16, 14)),
            )
            .show_separator_line(false)
            .show(ui, |ui| self.toolbar(ui));

        egui::Panel::top("progress")
            .frame(egui::Frame::new().fill(BORDER))
            .exact_size(3.0)
            .show_separator_line(false)
            .show(ui, |ui| {
                if self.scan.is_some() {
                    progress_bar(ui, self.progress());
                }
            });

        let selected = self
            .selected
            .filter(|_| self.show_details)
            .and_then(|address| {
                self.rows
                    .iter()
                    .find(|row| row.host.address == address)
                    .map(|row| (row.host.clone(), row.detailed))
            });
        if let Some((host, detailed)) = selected {
            egui::Panel::bottom("details")
                .frame(
                    egui::Frame::new()
                        .fill(SURFACE)
                        .inner_margin(egui::Margin::symmetric(20, 14))
                        .stroke(Stroke::new(1.0_f32, BORDER)),
                )
                .show(ui, |ui| {
                    if host_details(ui, &host, detailed) {
                        self.selected = None;
                    }
                });
        }

        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(BACKGROUND)
                    .inner_margin(egui::Margin::same(16)),
            )
            .show(ui, |ui| self.results(ui));
    }
}

/// Uses Segoe UI (crisp on Windows) instead of egui's thin default font.
fn setup_fonts(context: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    let directory = std::env::var_os("WINDIR")
        .map(|windir| PathBuf::from(windir).join("Fonts"))
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows\Fonts"));
    let mut load = |key: &str, file: &str| -> bool {
        match fs::read(directory.join(file)) {
            Ok(data) => {
                fonts
                    .font_data
                    .insert(key.to_owned(), Arc::new(egui::FontData::from_owned(data)));
                true
            }
            Err(_) => false,
        }
    };
    let regular = load("segoe", "segoeui.ttf");
    let bold = load(SEMIBOLD, "seguisb.ttf");
    let symbols = load("symbols", "seguisym.ttf");

    let mut proportional = fonts.families[&FontFamily::Proportional].clone();
    if symbols {
        proportional.insert(0, "symbols".to_owned());
    }
    if regular {
        proportional.insert(0, "segoe".to_owned());
    }
    let mut semibold_family = proportional.clone();
    if bold {
        semibold_family.insert(0, SEMIBOLD.to_owned());
    }
    fonts
        .families
        .insert(FontFamily::Proportional, proportional);
    fonts
        .families
        .insert(FontFamily::Name(SEMIBOLD.into()), semibold_family);
    context.set_fonts(fonts);
}

fn semibold(text: &str, size: f32) -> RichText {
    RichText::new(text)
        .family(FontFamily::Name(SEMIBOLD.into()))
        .size(size)
}

fn apply_theme(context: &egui::Context) {
    context.set_theme(egui::Theme::Light);
    context.style_mut_of(egui::Theme::Light, |style| {
        style.spacing.item_spacing = Vec2::new(8.0, 8.0);
        style.spacing.button_padding = Vec2::new(14.0, 7.0);
        style
            .text_styles
            .insert(egui::TextStyle::Body, FontId::proportional(14.0));
        style
            .text_styles
            .insert(egui::TextStyle::Button, FontId::proportional(14.0));

        let visuals = &mut style.visuals;
        // Hinting snaps glyphs to the pixel grid; sub-pixel binning blurs them.
        visuals.text_options.font_hinting = true;
        visuals.text_options.subpixel_binning = false;
        visuals.panel_fill = BACKGROUND;
        visuals.window_fill = SURFACE;
        visuals.extreme_bg_color = SURFACE;
        visuals.faint_bg_color = BACKGROUND;
        visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, TEXT);
        visuals.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, TEXT);
        visuals.selection.bg_fill = ACCENT_SOFT;
        visuals.selection.stroke = Stroke::new(1.0_f32, ACCENT);
        let radius = CornerRadius::same(6);
        for widget in [
            &mut visuals.widgets.noninteractive,
            &mut visuals.widgets.inactive,
            &mut visuals.widgets.hovered,
            &mut visuals.widgets.active,
            &mut visuals.widgets.open,
        ] {
            widget.corner_radius = radius;
        }
        visuals.widgets.inactive.bg_fill = Color32::from_rgb(236, 239, 243);
        visuals.widgets.inactive.weak_bg_fill = SURFACE;
        visuals.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, Color32::from_rgb(203, 210, 220));
        visuals.widgets.hovered.weak_bg_fill = BACKGROUND;
        visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, Color32::from_rgb(203, 210, 220));
        visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, BORDER);
    });
}

fn segmented(ui: &mut egui::Ui, depth: &mut ScanDepth) {
    egui::Frame::new()
        .fill(BACKGROUND)
        .stroke(Stroke::new(1.0_f32, BORDER))
        .corner_radius(CornerRadius::same(7))
        .inner_margin(egui::Margin::same(2))
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.x = 2.0;
            // The toolbar is laid out right to left.
            for option in ScanDepth::ALL.into_iter().rev() {
                let active = *depth == option;
                let text = if active {
                    semibold(option.label(), 14.0).color(ACCENT)
                } else {
                    RichText::new(option.label()).color(MUTED)
                };
                let button = egui::Button::new(text)
                    .fill(if active {
                        SURFACE
                    } else {
                        Color32::TRANSPARENT
                    })
                    .stroke(if active {
                        Stroke::new(1.0_f32, BORDER)
                    } else {
                        Stroke::NONE
                    })
                    .min_size(Vec2::new(76.0, 30.0));
                if ui.add(button).on_hover_text(option.hint()).clicked() {
                    *depth = option;
                }
            }
        });
}

fn progress_bar(ui: &mut egui::Ui, fraction: f32) {
    let rect = ui.max_rect();
    let painter = ui.painter();
    painter.rect_filled(rect, 0.0, ACCENT_SOFT);
    let mut filled = rect;
    filled.set_width(rect.width() * fraction.clamp(0.0, 1.0));
    painter.rect_filled(filled, 0.0, ACCENT);

    // Moving highlight so activity stays visible even when progress stalls.
    let time = ui.input(|input| input.time) as f32;
    let width = rect.width() * 0.2;
    let x = rect.left() + (time * 0.5).fract() * (rect.width() + width) - width;
    let shine = egui::Rect::from_min_max(
        egui::pos2(x.max(rect.left()), rect.top()),
        egui::pos2((x + width).min(rect.right()), rect.bottom()),
    );
    if shine.width() > 0.0 {
        painter.rect_filled(
            shine,
            0.0,
            Color32::from_rgba_unmultiplied(96, 165, 250, 200),
        );
    }
}

fn header_row(
    ui: &mut egui::Ui,
    columns: &[(Column, f32)],
    sort: (Column, bool),
) -> Option<Column> {
    let (rect, _) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), ROW_HEIGHT), Sense::hover());
    ui.painter()
        .hline(rect.x_range(), rect.bottom(), Stroke::new(1.0_f32, BORDER));
    let mut clicked = None;
    let mut x = rect.left();
    for &(column, width) in columns {
        let cell =
            egui::Rect::from_min_size(egui::pos2(x, rect.top()), Vec2::new(width, ROW_HEIGHT))
                .intersect(rect);
        let response = ui
            .interact(
                cell,
                egui::Id::unique(("header", column.title())),
                Sense::click(),
            )
            .on_hover_cursor(egui::CursorIcon::PointingHand);
        let active = sort.0 == column;
        let mut text = column.title().to_owned();
        if active {
            text.push_str(if sort.1 { "  ▲" } else { "  ▼" });
        }
        let color = if active || response.hovered() {
            TEXT
        } else {
            MUTED
        };
        ui.painter().text(
            cell.left_center() + Vec2::new(14.0, 0.0),
            Align2::LEFT_CENTER,
            text,
            FontId::new(12.5, FontFamily::Name(SEMIBOLD.into())),
            color,
        );
        if response.clicked() {
            clicked = Some(column);
        }
        x += width;
    }
    clicked
}

fn cell_text(column: Column, row: &Row) -> (String, Color32) {
    let host = &row.host;
    let pending = || ("…".to_owned(), MUTED);
    let empty = || ("—".to_owned(), MUTED);
    match column {
        Column::Address => (host.address.to_string(), TEXT),
        Column::Name => match &host.hostname {
            Some(name) => (name.clone(), TEXT),
            None if row.detailed => empty(),
            None => pending(),
        },
        Column::Vendor => match vendor_of(host) {
            Some(vendor::RANDOM_MAC) => (vendor::RANDOM_MAC.to_owned(), MUTED),
            Some(name) => (name.to_owned(), TEXT),
            None => empty(),
        },
        Column::Services if !row.detailed => pending(),
        Column::Services if host.services.is_empty() => empty(),
        Column::Services => (services_summary(host), TEXT),
        Column::Mac => match &host.mac_address {
            Some(mac) => (mac.clone(), MUTED),
            None => empty(),
        },
    }
}

fn host_row(
    ui: &mut egui::Ui,
    columns: &[(Column, f32)],
    row: &Row,
    selected: bool,
) -> egui::Response {
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), ROW_HEIGHT), Sense::click());
    let painter = ui.painter();
    if selected {
        painter.rect_filled(rect, 0.0, ACCENT_SOFT);
    } else if response.hovered() {
        painter.rect_filled(rect, 0.0, BACKGROUND);
    }
    painter.hline(rect.x_range(), rect.bottom(), Stroke::new(1.0_f32, BORDER));

    let mut x = rect.left();
    for &(column, width) in columns {
        let (text, color) = cell_text(column, row);
        let cell = egui::Rect::from_min_size(
            egui::pos2(x, rect.top()),
            Vec2::new(width - 8.0, ROW_HEIGHT),
        )
        .intersect(rect);
        painter.with_clip_rect(cell).text(
            cell.left_center() + Vec2::new(14.0, 0.0),
            Align2::LEFT_CENTER,
            text,
            FontId::proportional(14.0),
            color,
        );
        x += width;
    }
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// Returns true when the close button was pressed.
fn host_details(ui: &mut egui::Ui, host: &HostResult, detailed: bool) -> bool {
    let mut close = false;
    ui.horizontal(|ui| {
        ui.label(semibold(&host.address.to_string(), 18.0));
        if let Some(hostname) = &host.hostname {
            ui.label(RichText::new(hostname).size(15.0).color(MUTED));
        }
        if !detailed {
            ui.add(egui::Spinner::new().size(14.0).color(ACCENT));
        }
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            close = ui
                .add(egui::Button::new(RichText::new("×").size(20.0).color(MUTED)).frame(false))
                .on_hover_text("Cerrar")
                .clicked();
        });
    });
    ui.add_space(4.0);

    egui::Grid::new("details")
        .num_columns(2)
        .spacing([24.0, 6.0])
        .show(ui, |ui| {
            if let Some(mac) = &host.mac_address {
                match vendor_of(host) {
                    Some(name) => detail(ui, "MAC", &format!("{mac}  ·  {name}")),
                    None => detail(ui, "MAC", mac),
                }
            }
            if !host.services.is_empty() {
                ui.label(RichText::new("Puertos").color(MUTED));
                ui.horizontal_wrapped(|ui| {
                    for service in &host.services {
                        chip(ui, service.port, &service.name);
                    }
                });
                ui.end_row();
            }
            if let Some(http) = &host.http {
                let web = [http.title.as_deref(), http.server.as_deref()]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join(" · ");
                if !web.is_empty() {
                    detail(ui, "Web", &web);
                }
            }
            if !host.users.is_empty() {
                detail(ui, "Usuarios", &host.users.join(", "));
            }
            if !host.shares.is_empty() {
                let shares = host
                    .shares
                    .iter()
                    .map(|share| share.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                detail(ui, "Recursos", &shares);
            }
            if let Some(time) = &host.remote_time {
                detail(ui, "Hora", time);
            }
        });
    close
}

fn detail(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.label(RichText::new(label).color(MUTED));
    ui.label(value);
    ui.end_row();
}

fn chip(ui: &mut egui::Ui, port: u16, name: &str) {
    egui::Frame::new()
        .fill(ACCENT_SOFT)
        .corner_radius(CornerRadius::same(10))
        .inner_margin(egui::Margin::symmetric(8, 2))
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.x = 4.0;
            ui.label(semibold(&port.to_string(), 13.0).color(ACCENT));
            ui.label(RichText::new(name).size(13.0).color(ACCENT));
        });
}

fn services_summary(host: &HostResult) -> String {
    host.services
        .iter()
        .map(|service| format!("{} {}", service.port, service.name))
        .collect::<Vec<_>>()
        .join(",  ")
}

fn first_port(host: &HostResult) -> u16 {
    host.services
        .first()
        .map(|service| service.port)
        .unwrap_or(u16::MAX)
}

/// Text comparison with empty values always last.
fn compare_text(a: Option<&str>, b: Option<&str>) -> CmpOrdering {
    match (a, b) {
        (Some(a), Some(b)) => a.to_lowercase().cmp(&b.to_lowercase()),
        (Some(_), None) => CmpOrdering::Less,
        (None, Some(_)) => CmpOrdering::Greater,
        (None, None) => CmpOrdering::Equal,
    }
}

fn vendor_of(host: &HostResult) -> Option<&'static str> {
    host.mac_address.as_deref().and_then(vendor::lookup)
}

fn searchable(host: &HostResult) -> String {
    format!(
        "{} {} {} {} {}",
        host.address,
        host.hostname.as_deref().unwrap_or_default(),
        host.mac_address.as_deref().unwrap_or_default(),
        vendor_of(host).unwrap_or_default(),
        services_summary(host)
    )
    .to_lowercase()
}

fn range_text(network: &LocalNetwork) -> String {
    let (start, end) = network.host_range();
    if start == end {
        start.to_string()
    } else {
        format!("{start}-{end}")
    }
}

/// Physical adapters first, virtual/VPN adapters last.
fn adapter_rank(name: &str) -> u8 {
    let name = name.to_lowercase();
    let is_virtual = [
        "vethernet",
        "virtualbox",
        "vmware",
        "hyper-v",
        "wsl",
        "docker",
        "vpn",
        "tailscale",
        "zerotier",
        "wt0",
        "tun",
        "tap",
    ]
    .iter()
    .any(|keyword| name.contains(keyword));
    if is_virtual {
        2
    } else if ["ethernet", "wi-fi", "wifi", "wlan"]
        .iter()
        .any(|keyword| name.contains(keyword))
    {
        0
    } else {
        1
    }
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}

fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    if seconds >= 60 {
        format!("{}m {:02}s", seconds / 60, seconds % 60)
    } else if seconds > 0 {
        format!("{:.1} s", duration.as_secs_f32())
    } else {
        format!("{} ms", duration.as_millis())
    }
}
