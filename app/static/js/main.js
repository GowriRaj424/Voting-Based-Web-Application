document.addEventListener("DOMContentLoaded", function () {
  console.log("Main JS Loaded");

  // Initialize Select2 (if using for dropdowns)
  if (typeof jQuery !== "undefined" && jQuery().select2) {
    $(".form-control").select2();
  }

  // Handle Poll Creation Form Submission
  const createPollForm = document.querySelector("#create-poll-form");
  if (createPollForm) {
    createPollForm.addEventListener("submit", function (e) {
      e.preventDefault();
      const formData = new FormData(createPollForm);
      console.log("Creating Poll:", Object.fromEntries(formData.entries()));

      // AJAX example (optional):
      fetch("/create_poll", {
        method: "POST",
        body: formData,
      })
        .then((response) => response.json())
        .then((data) => {
          console.log("Poll Created Successfully:", data);
          alert("Poll Created Successfully!");
        })
        .catch((error) => console.error("Error:", error));
    });
  }

  // Handle Voting Form Submission
  const addVoteForm = document.querySelector("#add-vote-form");
  if (addVoteForm) {
    addVoteForm.addEventListener("submit", function (e) {
      e.preventDefault();
      const formData = new FormData(addVoteForm);
      console.log("Casting Vote:", Object.fromEntries(formData.entries()));

      // AJAX example (optional):
      fetch("/add_vote", {
        method: "POST",
        body: formData,
      })
        .then((response) => response.json())
        .then((data) => {
          console.log("Vote Submitted Successfully:", data);
          alert("Vote Submitted Successfully!");
        })
        .catch((error) => console.error("Error:", error));
    });
  }

  // Handle Table Pagination (Optional)
  const paginationLinks = document.querySelectorAll(".pagination a");
  if (paginationLinks) {
    paginationLinks.forEach((link) => {
      link.addEventListener("click", function (e) {
        e.preventDefault();
        const page = this.getAttribute("data-page");
        console.log("Loading Page:", page);
        // Logic for loading data for the specified page goes here
      });
    });
  }

  // Example: Toggle Poll Status
  const toggleButtons = document.querySelectorAll(".toggle");
  if (toggleButtons) {
    toggleButtons.forEach((toggle) => {
      toggle.addEventListener("click", function () {
        const pollId = this.getAttribute("data-poll-id");
        const newStatus = this.classList.contains("active")
          ? "inactive"
          : "active";
        console.log("Toggling Status for Poll:", pollId, "to", newStatus);

        // Update UI
        this.classList.toggle("active");
      });
    });
  }
});
