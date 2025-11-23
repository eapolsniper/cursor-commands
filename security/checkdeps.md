# checkdeps

Write your command content here.
# checkdeps

Write your command content here.

You will run a read-only analysis of dependencies. You will not create any files or scripts. You will only conduct analysis through model data or connections you can do to live data sources.

"Analyze all dependency files in this project. Identify and list all direct and indirect (transitive) dependency package names and their exact versions. Present the output as a Markdown table with 'Package Name' and 'Version' columns.

"Using your internal knowledge base and public information up to your last training cutoff, perform a specialized supply chain risk assessment for every package in the following list. Focus only on the qualitative, hard-to-detect risks, ignoring standard CVEs.

For each package, determine and report the risk level (Low, Medium, High, Critical) based on the following criteria:

Maintenance Health: Is the package considered stale or unmaintained (e.g., no updates, commits, or releases in the last 18+ months)?

Developer Concentration: Is it primarily maintained by one or two developers (High 'Bus Factor')?

Typosquatting Risk: Does the name highly resemble a popular, legitimate package (i.e., is it likely a typosquatting attempt)?

Geopolitical Risk/Reputation: Are there known or reported ties to sanctioned countries or high-risk nation-state attacker groups?

Output a new Markdown table with columns: 'Package Name', 'Version', 'Highest Risk Level', and a brief 'Reason for Risk' (e.g., 'Stale; 1 Maintainer', 'Possible Typosquat of React', 'Ties to Sanctioned Entity').

Review the risk assessment table generated so far. Filter the results to show ONLY packages flagged with 'High' or 'Critical' risk levels.

Then, generate a concise, professional notification block for a US-based Application Security Engineer. This notification must:

Start with a clear 🚨 CRITICAL ALERT message.

List the affected packages and their primary risk reasons in an easy-to-read bulleted list.

State that the user must perform an immediate manual security review for each listed item.

create or overwite a file called DEPENDENCY_RISK_ASSESSMENT.md with the report in the root of the project.

Check if the repository is public or private. If the repository is public, add the CDEPENDENCY_RISK_ASSESSMENT.md file to the gitignore so it does not get discosed. If you can't tell, default to adding the file to gitignore.

This command will be available in chat with /checkdeps
