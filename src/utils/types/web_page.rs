/// This enum defines the possible web pages to be opened.
#[derive(Debug, Clone)]
pub enum WebPage {
    /// Netwatch's GitHub repository.
    Repo,
    // /// Netwatch's website main page.
    // Website,
    /// Netwatch's website/download page.
    WebsiteDownload,
    /// Netwatch's website/news page.
    WebsiteNews,
    /// Netwatch's website/sponsor page.
    WebsiteSponsor,
    /// Netwatch Roadmap
    Roadmap,
    // /// Netwatch issues on GitHub
    // Issues,
    /// Netwatch issue #60 on GitHub
    IssueLanguages,
    /// Netwatch Wiki
    Wiki,
    /// My GitHub profile
    MyGitHub,
}

impl WebPage {
    pub fn get_url(&self) -> &str {
        match self {
            WebPage::Repo => "https://github.com/0xZenithdev/NetWatch-x",
            // WebPage::Website => "https://github.com/0xZenithdev/NetWatch-x",
            WebPage::WebsiteSponsor => "https://github.com/0xZenithdev/NetWatch-x/sponsor/",
            WebPage::WebsiteDownload => "https://github.com/0xZenithdev/NetWatch-x/download/",
            WebPage::WebsiteNews => "https://github.com/0xZenithdev/NetWatch-x/news/",
            WebPage::Roadmap => "https://whimsical.com/netwatch-roadmap-Damodrdfx22V9jGnpHSCGo",
            // WebPage::Issues => "https://github.com/0xZenithdev/NetWatch-x/issues",
            WebPage::IssueLanguages => "https://github.com/0xZenithdev/NetWatch-x/issues/60",
            WebPage::Wiki => "https://github.com/0xZenithdev/NetWatch-x/wiki",
            WebPage::MyGitHub => "https://github.com/GyulyVGC",
        }
    }
}
