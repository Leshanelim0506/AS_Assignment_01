using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AS_Assignment_01.Migrations
{
    /// <inheritdoc />
    public partial class AceJobAgencyUpdate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AboutMe",
                table: "AspNetUsers");

            migrationBuilder.RenameColumn(
                name: "PhotoPath",
                table: "AspNetUsers",
                newName: "WhoAmI");

            migrationBuilder.RenameColumn(
                name: "MobileNo",
                table: "AspNetUsers",
                newName: "ResumePath");

            migrationBuilder.RenameColumn(
                name: "FullName",
                table: "AspNetUsers",
                newName: "LastName");

            migrationBuilder.RenameColumn(
                name: "EncryptedCreditCard",
                table: "AspNetUsers",
                newName: "FirstName");

            migrationBuilder.RenameColumn(
                name: "DeliveryAddress",
                table: "AspNetUsers",
                newName: "EncryptedNRIC");

            migrationBuilder.AddColumn<DateTime>(
                name: "DateOfBirth",
                table: "AspNetUsers",
                type: "datetime2",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "DateOfBirth",
                table: "AspNetUsers");

            migrationBuilder.RenameColumn(
                name: "WhoAmI",
                table: "AspNetUsers",
                newName: "PhotoPath");

            migrationBuilder.RenameColumn(
                name: "ResumePath",
                table: "AspNetUsers",
                newName: "MobileNo");

            migrationBuilder.RenameColumn(
                name: "LastName",
                table: "AspNetUsers",
                newName: "FullName");

            migrationBuilder.RenameColumn(
                name: "FirstName",
                table: "AspNetUsers",
                newName: "EncryptedCreditCard");

            migrationBuilder.RenameColumn(
                name: "EncryptedNRIC",
                table: "AspNetUsers",
                newName: "DeliveryAddress");

            migrationBuilder.AddColumn<string>(
                name: "AboutMe",
                table: "AspNetUsers",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");
        }
    }
}
