# SNX VPN — Component Dependency Graph

Generated: 2026-02-28

## Full Architecture

```mermaid
graph TD
    %% Entry point
    APP[snxui.app\nSNXApplication]

    %% Presentation layer
    subgraph UI ["Presentation Layer (GTK4 + Libadwaita)"]
        MW[MainWindow]
        HP[HomePage]
        PP[ProfilesPage]
        SP[SettingsPage]
        DL[Dialogs\nPasswordDialog\nProfileDialog\nAboutDialog]
    end

    %% Business layer
    subgraph CORE ["Business Layer (Core)"]
        TYPES[types\nProfile\nConnectionStatus\nConnectionState]
        PM[ProfileManager]
        CS[CredentialStore]
        SB[SNXBackend]
    end

    %% Infrastructure layer
    subgraph SYS ["Infrastructure Layer (System)"]
        TM[TrayManager]
        AM[AutostartManager]
        PH[PrivilegeHandler]
    end

    %% External
    subgraph EXT ["External"]
        SNX[(SNX binary)]
        KR[(Keyring\nlibsecret /\nKDE Wallet)]
        DBUS[(D-Bus\nsession bus)]
        POLKIT[(polkit /\npkexec)]
    end

    %% SNXApplication wires everything
    APP --> MW
    APP --> PM
    APP --> CS
    APP --> SB
    APP --> TM
    APP --> AM

    %% MainWindow -> pages
    MW --> HP
    MW --> PP
    MW --> SP
    MW --> DL
    MW --> TM

    %% HomePage
    HP --> PM
    HP --> CS
    HP --> SB
    HP --> DL
    HP --> TYPES

    %% ProfilesPage
    PP --> PM
    PP --> CS
    PP --> DL

    %% SettingsPage
    SP --> AM

    %% Dialogs
    DL --> TYPES

    %% Core -> types
    PM --> TYPES
    SB --> TYPES

    %% Core -> external
    SB --> SNX
    CS --> KR
    TM --> DBUS
    PH --> POLKIT
    PH --> SNX

    %% Styling by layer
    style APP fill:#fff4e1,stroke:#f0a000
    style MW fill:#e1f5ff,stroke:#0080c0
    style HP fill:#e1f5ff,stroke:#0080c0
    style PP fill:#e1f5ff,stroke:#0080c0
    style SP fill:#e1f5ff,stroke:#0080c0
    style DL fill:#e1f5ff,stroke:#0080c0
    style TYPES fill:#fff4e1,stroke:#f0a000
    style PM fill:#fff4e1,stroke:#f0a000
    style CS fill:#fff4e1,stroke:#f0a000
    style SB fill:#fff4e1,stroke:#f0a000
    style TM fill:#e1ffe1,stroke:#00a040
    style AM fill:#e1ffe1,stroke:#00a040
    style PH fill:#e1ffe1,stroke:#00a040
    style SNX fill:#f0f0f0,stroke:#808080
    style KR fill:#f0f0f0,stroke:#808080
    style DBUS fill:#f0f0f0,stroke:#808080
    style POLKIT fill:#f0f0f0,stroke:#808080
```

## Layer Legend

| Color | Layer | Responsibility |
|-------|-------|----------------|
| Light blue `#e1f5ff` | Presentation | GTK4 + Libadwaita UI widgets |
| Light yellow `#fff4e1` | Business | Domain logic, VPN automation, persistence |
| Light green `#e1ffe1` | Infrastructure | OS integration (D-Bus, XDG, polkit) |
| Gray `#f0f0f0` | External | Processes and OS services owned outside the app |

## Module-level Dependencies

```mermaid
graph LR
    subgraph snxui
        APP2[app.py]
        subgraph core
            INIT_C[__init__.py]
            T2[types.py]
            PM2[profile_manager.py]
            CS2[credential_store.py]
            SB2[snx_backend.py]
        end
        subgraph ui
            INIT_U[__init__.py]
            MW2[main_window.py]
            HP2[home_page.py]
            PP2[profiles_page.py]
            SP2[settings_page.py]
            DL2[dialogs.py]
        end
        subgraph system
            INIT_S[__init__.py]
            TM2[tray_manager.py]
            AM2[autostart.py]
            PH2[privilege_handler.py]
        end
    end

    APP2 --> INIT_C
    APP2 --> INIT_S
    APP2 --> MW2

    INIT_C --> T2
    INIT_C --> PM2
    INIT_C --> CS2
    INIT_C --> SB2

    SB2 --> T2
    PM2 --> T2

    INIT_S --> TM2
    INIT_S --> AM2
    INIT_S --> PH2

    INIT_U --> MW2
    MW2 --> HP2
    MW2 --> PP2
    MW2 --> SP2

    HP2 --> DL2
    PP2 --> DL2
    DL2 --> T2
    HP2 --> T2
```
